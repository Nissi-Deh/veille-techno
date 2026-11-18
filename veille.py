#!/usr/bin/env python3
"""Veille technologique : collecte, filtre, dédoublonne et alerte via Telegram.

Usage :
    python veille.py poll      # collecte + alertes immédiates (toutes les 5 min)
    python veille.py digest    # envoie le résumé quotidien
    python veille.py check     # teste toutes les sources sans rien envoyer

Variables d'environnement : TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
Sans token, les messages sont simplement affichés (mode essai).
"""
import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

import config as cfg

STATE_DIR = Path(__file__).parent / "state"
SEEN_FILE = STATE_DIR / "seen.json"
DIGEST_FILE = STATE_DIR / "digest.json"
FAILS_FILE = STATE_DIR / "fails.json"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; veille-bot/1.0)"}


# ---------- utilitaires ----------

def load(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save(path, data):
    STATE_DIR.mkdir(exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def esc(text):
    return html.escape(str(text), quote=True)


def clean(text):
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def kw_regex(words):
    return re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + ")", re.I)


CRITICAL_RE = kw_regex(cfg.CRITICAL_KEYWORDS)
WATCH_RE = kw_regex(cfg.WATCH_KEYWORDS)
IGNORE_RE = kw_regex(cfg.IGNORE_KEYWORDS)


# ---------- Telegram ----------

def tg_send(text):
    token = os.environ.get("TELEGRAM_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        print("[essai, pas de token Telegram]\n" + text + "\n")
        return
    r = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat, "text": text, "parse_mode": "HTML",
              "disable_web_page_preview": True},
        timeout=20,
    )
    r.raise_for_status()


# ---------- récupération des sources ----------

def fetch_rss(src):
    r = requests.get(src["url"], headers=HEADERS, timeout=20)
    r.raise_for_status()
    feed = feedparser.parse(r.content)
    if feed.bozo and not feed.entries:
        raise ValueError("flux illisible")
    items = []
    for e in feed.entries[: cfg.MAX_ITEMS_PER_SOURCE]:
        link = e.get("link", "")
        items.append({
            "id": e.get("id") or link or e.get("title", ""),
            "title": clean(e.get("title", "")),
            "link": link,
            "summary": clean(e.get("summary", ""))[:300],
        })
    return items


def fetch_kev(src):
    r = requests.get(src["url"], headers=HEADERS, timeout=30)
    r.raise_for_status()
    vulns = sorted(r.json()["vulnerabilities"], key=lambda v: v["dateAdded"], reverse=True)
    items = []
    for v in vulns[: cfg.MAX_ITEMS_PER_SOURCE]:
        items.append({
            "id": v["cveID"],
            "title": f'{v["cveID"]} : {v["vendorProject"]} {v["product"]}, {v["vulnerabilityName"]}',
            "link": f'https://nvd.nist.gov/vuln/detail/{v["cveID"]}',
            "summary": clean(v.get("shortDescription", ""))[:300],
        })
    return items


FETCHERS = {"rss": fetch_rss, "kev": fetch_kev}


def fetch_all():
    results = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(FETCHERS[s.get("type", "rss")], s): s for s in cfg.SOURCES}
        for f in as_completed(futs):
            name = futs[f]["name"]
            try:
                results[name] = f.result()
            except Exception as e:  # noqa: BLE001
                results[name] = e
    return results


# ---------- classification ----------

def classify(src, item):
    """Retourne 'alert', 'digest' ou None (ignoré)."""
    text = f'{item["title"]} {item["summary"]}'
    if IGNORE_RE.search(text):
        return None
    mode = src["mode"]
    if mode == "alert":
        return "alert"
    if CRITICAL_RE.search(text):
        return "alert"
    if mode == "smart" or mode == "digest":
        return "digest"
    if mode == "filtered":
        return "digest" if WATCH_RE.search(text) else None
    return None


def format_alert(src, item):
    parts = [f'🔴 <b>{esc(item["title"][:200])}</b>',
             f'<i>{esc(src["name"])} · {esc(src["cat"])}</i>']
    if item["summary"]:
        parts.append(esc(item["summary"][:250]))
    if item["link"]:
        parts.append(f'<a href="{esc(item["link"])}">Ouvrir</a>')
    return "\n".join(parts)


# ---------- commandes ----------

def poll():
    seen = load(SEEN_FILE, {})
    first_run = not seen
    digest = load(DIGEST_FILE, [])
    fails = load(FAILS_FILE, {})
    results = fetch_all()
    now = time.time()
    pushed = 0
    new_total = 0

    for src in cfg.SOURCES:
        name = src["name"]
        res = results[name]
        if isinstance(res, Exception):
            print(f"[échec] {name}: {res}")
            if not src.get("optional"):
                fails[name] = fails.get(name, 0) + 1
                if fails[name] == cfg.FAIL_ALERT_AFTER:
                    try:
                        tg_send(f"⚠️ <b>Source en échec</b> depuis {cfg.FAIL_ALERT_AFTER} passages : "
                                f"{esc(name)}\n{esc(str(res)[:200])}")
                    except Exception as e:  # noqa: BLE001
                        print(f"[telegram] {e}")
            continue
        fails[name] = 0

        for item in reversed(res):  # du plus ancien au plus récent
            key = f'{name}|{item["id"]}'
            if key in seen:
                continue
            seen[key] = now
            new_total += 1
            if first_run:
                continue  # amorçage : on mémorise sans envoyer
            level = classify(src, item)
            if level is None:
                continue
            if level == "alert" and pushed < cfg.MAX_PUSH_PER_RUN:
                try:
                    tg_send(format_alert(src, item))
                    pushed += 1
                    continue
                except Exception as e:  # noqa: BLE001
                    print(f"[telegram] {e}")
                    del seen[key]  # on retentera au prochain passage
                    continue
            digest.append({"cat": src["cat"], "src": name, "title": item["title"],
                           "link": item["link"], "t": now})

    # purge de l'historique
    if len(seen) > cfg.SEEN_LIMIT:
        keep = sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[: cfg.SEEN_LIMIT]
        seen = dict(keep)

    save(SEEN_FILE, seen)
    save(DIGEST_FILE, digest)
    save(FAILS_FILE, fails)

    if first_run:
        try:
            tg_send(f"✅ <b>Veille initialisée</b>\n{new_total} éléments mémorisés. "
                    f"Tu recevras désormais uniquement les nouveautés.")
        except Exception as e:  # noqa: BLE001
            print(f"[telegram] {e}")
    print(f"ok : {new_total} nouveaux, {pushed} alertes, {len(digest)} en attente de résumé")


def send_digest():
    queue = load(DIGEST_FILE, [])
    if not queue:
        print("résumé vide")
        return
    by_cat = {}
    for it in queue:
        by_cat.setdefault(it["cat"], []).append(it)
    tz = timezone(timedelta(hours=cfg.TZ_OFFSET_HOURS))
    day = datetime.now(tz).strftime("%d/%m/%Y")
    blocks = [f"📰 <b>Résumé veille du {day}</b> ({len(queue)} infos)"]
    for cat, items in by_cat.items():
        lines = [f"\n<b>{esc(cat)}</b>"]
        for it in items[: cfg.DIGEST_MAX_PER_CAT]:
            lines.append(f'• <a href="{esc(it["link"])}">{esc(it["title"][:140])}</a> '
                         f'<i>({esc(it["src"])})</i>')
        extra = len(items) - cfg.DIGEST_MAX_PER_CAT
        if extra > 0:
            lines.append(f"… et {extra} autres")
        blocks.append("\n".join(lines))
    chunk = ""
    for b in blocks:
        if chunk and len(chunk) + len(b) > 3800:
            tg_send(chunk)
            chunk = ""
        chunk += b + "\n"
    if chunk:
        tg_send(chunk)
    save(DIGEST_FILE, [])  # vidé seulement si l'envoi a réussi
    print(f"résumé envoyé ({len(queue)} infos)")


def check():
    results = fetch_all()
    bad = 0
    for src in cfg.SOURCES:
        res = results[src["name"]]
        if isinstance(res, Exception):
            bad += 1
            print(f'❌ {src["name"]:32} {str(res)[:90]}')
        else:
            print(f'✅ {src["name"]:32} {len(res)} éléments')
    print(f"\n{len(cfg.SOURCES) - bad}/{len(cfg.SOURCES)} sources OK")
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "poll"
    if cmd == "poll":
        poll()
    elif cmd == "digest":
        send_digest()
    elif cmd == "check":
        check()
    else:
        sys.exit(__doc__)
