# Veille technologique automatisée

Surveille des pages de statut cloud, des flux de cybersécurité (CISA KEV, CERT-FR), l'IA, l'actu IT et le Cameroun / Afrique.
Les infos critiques arrivent tout de suite sur Telegram, le reste dans un résumé quotidien à 07h00 (Douala).

## Mise en place (15 minutes)

1. **Bot Telegram** : sur Telegram, ouvre `@BotFather`, envoie `/newbot`, garde le **token**.
2. **Ton chat id** : écris un message à ton bot, puis ouvre
   `https://api.telegram.org/bot<TOKEN>/getUpdates` et note `message.chat.id`.
3. **Dépôt GitHub public** : crée-le, puis pousse ce dossier dedans.
   Public est important : les minutes GitHub Actions sont illimitées, alors qu'un dépôt privé
   n'a que 2000 min/mois et ce système en consomme beaucoup plus. Aucun secret n'est dans le code.
4. **Secrets** : Settings > Secrets and variables > Actions > New repository secret :
   `TELEGRAM_TOKEN` et `TELEGRAM_CHAT_ID`.
5. **Test des sources** : onglet Actions > veille > Run workflow > mode `check`, regarde les logs.
   Corrige ou supprime dans `config.py` les flux marqués ❌ (les URL de flux changent parfois).
6. **Lancement** : Run workflow en mode `poll`. Tu reçois « Veille initialisée ». Ensuite c'est automatique.

## Essai en local

```bash
pip install -r requirements.txt
python veille.py check          # teste les sources
python veille.py poll           # sans token : affiche au lieu d'envoyer
```

## Personnaliser

Tout est dans `config.py` : sources, mots-clés critiques, mots surveillés, mots ignorés, limites.
Modes d'une source : `alert` (tout en direct), `smart` (critique en direct, reste en résumé),
`filtered` (critique en direct, mots surveillés en résumé, sinon ignoré), `digest` (résumé seulement).

## Limites à connaître

- GitHub Actions passe toutes les 5 minutes au mieux, avec parfois quelques minutes de retard.
  Pour du vrai temps réel à la minute, il faudra migrer vers une VM toujours allumée.
- Microsoft 365 n'a pas de flux public officiel : Outlook est détecté par recoupement (Google Actualités,
  Hacker News, r/sysadmin) et non via l'API Graph, donc avec un léger retard possible.
- Reddit bloque souvent les adresses de GitHub : cette source est marquée `optional`.
- Si une source échoue 12 fois de suite (environ 1 h), tu reçois une alerte « Source en échec ».
- L'état (`state/`) est sauvegardé par un commit automatique dans le dépôt quand il change.
