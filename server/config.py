# ============================================================
#  server/config.py — Configuration centralisée
#  Rôle        : Définit toutes les constantes du serveur C2
#  Importé par : database.py, storage.py, cleanup.py, routes.*, main.py
#  Dépend de   : Aucun (module racine)
# ============================================================

import os
from pathlib import Path

# ── Réseau ──────────────────────────────────────────────────
HOST                  = "0.0.0.0"
PORT                  = 8000
BASE_URL              = f"http://{HOST}:{PORT}"

# ── Agent ───────────────────────────────────────────────────
AGENT_TIMEOUT         = 30      # secondes sans poll → offline
CLEANUP_INTERVAL      = 60      # fréquence scan nettoyage (secondes)
CLEANUP_THRESHOLD     = 300     # inactivité → lost + suppression 
DEFAULT_POLL_INTERVAL = 3       # interval poll agent (secondes)
DEFAULT_JITTER        = 0.5     # 50% jitter sur poll interval
CMD_TIMEOUT           = 10      # timeout exécution commande agent

# ── Sessions ────────────────────────────────────────────────
SESSION_TIMEOUT       = 28800   # 8 heures en secondes

# ── Base de données ─────────────────────────────────────────
DB_PATH               = Path(__file__).parent / "c2_phase2.db"

# ── Logs ────────────────────────────────────────────────────
LOG_MAX_ENTRIES       = 10000   # purge auto au-delà de cette limite