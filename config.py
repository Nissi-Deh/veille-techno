"""Configuration de la veille : sources, mots-clés, limites.

Modes d'une source :
  alert    : chaque nouvel élément déclenche une alerte immédiate
  smart    : alerte si mot-clé critique, sinon résumé quotidien
  filtered : alerte si mot-clé critique, résumé si mot-clé surveillé, sinon ignoré
  digest   : tout va dans le résumé quotidien
"""
from urllib.parse import quote_plus


def gnews(query, lang="fr", country="CM"):
    """Flux Google Actualités pour une recherche donnée."""
    return (
        "https://news.google.com/rss/search?q=" + quote_plus(query)
        + f"&hl={lang}&gl={country}&ceid={country}:{lang}"
    )


SOURCES = [
    # --- Pannes de services (alerte immédiate) ---
    {"name": "Azure Status", "cat": "Pannes", "mode": "alert",
     "url": "https://azurestatuscdn.azureedge.net/en-us/status/feed/"},
    {"name": "AWS Status", "cat": "Pannes", "mode": "alert",
     "url": "https://status.aws.amazon.com/rss/all.rss"},
    {"name": "Google Cloud Status", "cat": "Pannes", "mode": "alert",
     "url": "https://status.cloud.google.com/en/feed.atom"},
    {"name": "Cloudflare Status", "cat": "Pannes", "mode": "alert",
     "url": "https://www.cloudflarestatus.com/history.atom"},
    {"name": "GitHub Status", "cat": "Pannes", "mode": "alert",
     "url": "https://www.githubstatus.com/history.atom"},
    # Microsoft 365 n'a pas de flux RSS public officiel : on recoupe plusieurs signaux.
    {"name": "Outlook/M365 (Google News)", "cat": "Pannes", "mode": "filtered",
     "url": gnews('Outlook OR "Microsoft 365" OR Teams outage when:1d', "en", "US")},
    {"name": "Outlook/M365 (Hacker News)", "cat": "Pannes", "mode": "filtered",
     "url": "https://hnrss.org/newest?q=outlook+OR+microsoft+365+OR+azure+outage"},
    {"name": "r/sysadmin", "cat": "Pannes", "mode": "filtered", "optional": True,
     "url": "https://www.reddit.com/r/sysadmin/new/.rss"},

    # --- Cybersécurité ---
    {"name": "CISA KEV", "cat": "Cybersécurité", "mode": "alert", "type": "kev",
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    {"name": "CERT-FR alertes", "cat": "Cybersécurité", "mode": "alert",
     "url": "https://www.cert.ssi.gouv.fr/alerte/feed/"},
    {"name": "CERT-FR avis", "cat": "Cybersécurité", "mode": "smart",
     "url": "https://www.cert.ssi.gouv.fr/avis/feed/"},
    {"name": "BleepingComputer", "cat": "Cybersécurité", "mode": "smart",
     "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "cat": "Cybersécurité", "mode": "smart",
     "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "cat": "Cybersécurité", "mode": "smart",
     "url": "https://krebsonsecurity.com/feed/"},

    # --- IA ---
    {"name": "OpenAI", "cat": "IA", "mode": "digest",
     "url": "https://openai.com/news/rss.xml"},
    {"name": "Hugging Face", "cat": "IA", "mode": "digest",
     "url": "https://huggingface.co/blog/feed.xml"},
    {"name": "Hacker News (IA)", "cat": "IA", "mode": "digest",
     "url": "https://hnrss.org/newest?q=LLM+OR+Claude+OR+GPT+OR+Gemini&points=150"},

    # --- Actu IT générale ---
    {"name": "Hacker News (top)", "cat": "IT général", "mode": "digest",
     "url": "https://hnrss.org/frontpage?points=300"},
    {"name": "Ars Technica", "cat": "IT général", "mode": "digest",
     "url": "https://feeds.arstechnica.com/arstechnica/technology-lab"},
    {"name": "Le Monde Informatique", "cat": "IT général", "mode": "digest",
     "url": "https://www.lemondeinformatique.fr/flux-rss/thematique/toutes-les-actualites/rss.xml"},

    # --- Cameroun et Afrique ---
    {"name": "Pannes opérateurs CM", "cat": "Cameroun / Afrique", "mode": "smart",
     "url": gnews("(MTN OR Orange OR Camtel OR Nexttel) Cameroun (panne OR coupure OR perturbation) when:2d")},
    {"name": "ANTIC / cybersécurité CM", "cat": "Cameroun / Afrique", "mode": "smart",
     "url": gnews("(ANTIC OR cybersécurité OR cyberattaque) Cameroun when:3d")},
    {"name": "Numérique Afrique", "cat": "Cameroun / Afrique", "mode": "digest",
     "url": gnews("numérique télécoms Afrique Cameroun when:2d")},
]

# Une alerte immédiate est déclenchée si l'un de ces termes apparaît (modes smart / filtered).
CRITICAL_KEYWORDS = [
    "outage", "panne", "incident", "service disruption", "degraded", "indisponible",
    "is down", "went down", "goes down", "down for", "not working",
    "zero-day", "0-day", "actively exploited", "exploité activement", "exploitée",
    "ransomware", "data breach", "fuite de données", "critical vulnerability", "faille critique",
    "coupure", "cyberattaque",
]

# Termes qui rendent un élément digne du résumé quotidien (mode filtered).
WATCH_KEYWORDS = [
    "outlook", "microsoft 365", "office 365", "teams", "azure", "entra", "windows",
    "wazuh", "fortinet", "cisco", "palo alto", "vmware", "linux", "kubernetes", "docker",
    "mtn", "orange", "camtel", "cameroun", "cameroon",
]

# Les éléments contenant l'un de ces termes sont ignorés.
IGNORE_KEYWORDS = ["sponsored", "sponsorisé", "giveaway", "webinar", "promo"]

MAX_PUSH_PER_RUN = 8        # au-delà, les alertes excédentaires vont dans le résumé
MAX_ITEMS_PER_SOURCE = 25   # éléments les plus récents lus par source
SEEN_LIMIT = 6000           # taille maximale de l'historique de dédoublonnage
FAIL_ALERT_AFTER = 12       # alerte si une source échoue 12 fois de suite (environ 1 h)
DIGEST_MAX_PER_CAT = 12     # éléments affichés par catégorie dans le résumé
TZ_OFFSET_HOURS = 1         # Douala (UTC+1)
