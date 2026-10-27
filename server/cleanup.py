"""Nettoyage périodique des agents hors ligne/lost.

PROBLÈME ORIGINAL :
  cleanup tourne dans un thread daemon (sync).
  db.set_agent_status() / db.log_agent_event() sont maintenant async.
  → Appeler une coroutine async depuis un thread sync = RuntimeWarning "never awaited"

SOLUTION :
  asyncio.run_coroutine_threadsafe(coroutine, loop)
  → soumet la coroutine à la boucle asyncio principale
  → le thread attend le résultat avec .result()
  → propre, sans créer de nouvelle boucle à chaque appel
"""

import asyncio
import threading
import time

from config import CLEANUP_INTERVAL, AGENT_TIMEOUT, CLEANUP_THRESHOLD
import storage
import database as db


from typing import Optional

# ── Référence à la boucle asyncio principale ─────────────────
# Passée par main.py au démarrage via start_cleanup_thread()
# Permet d'exécuter des coroutines async depuis ce thread sync
_event_loop: Optional[asyncio.AbstractEventLoop] = None


def run_async(coro):
    """
    Exécute une coroutine async depuis un contexte synchrone (thread).

    Utilise asyncio.run_coroutine_threadsafe() pour soumettre
    la coroutine à la boucle asyncio principale du serveur.
    .result(timeout=10) attend la fin et retourne la valeur.

    Pourquoi pas asyncio.run() ?
      → asyncio.run() crée une NOUVELLE boucle à chaque appel
      → conflit avec aiosqlite qui utilise la boucle principale
      → run_coroutine_threadsafe() réutilise la boucle existante ✓
    """
    if _event_loop is None:
        return None
    try:
        future = asyncio.run_coroutine_threadsafe(coro, _event_loop)
        return future.result(timeout=10)   # attend max 10s
    except Exception as e:
        print(f"[CLEANUP] Erreur async: {e}")
        return None


def start_cleanup_thread(loop: asyncio.AbstractEventLoop):
    """
    Démarre le thread de nettoyage.
    loop → boucle asyncio principale passée depuis main.py lifespan.
    """
    global _event_loop
    _event_loop = loop   # stocke la référence pour run_async()

    cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
    cleanup_thread.start()
    print("[OK] Thread de nettoyage démarré")


def _cleanup_loop():
    """Boucle infinie de nettoyage — tourne en arrière-plan."""
    while True:
        try:
            time.sleep(CLEANUP_INTERVAL)
            _perform_cleanup()
        except Exception as e:
            # Log l'erreur mais continue — le thread ne doit jamais mourir
            run_async(db.log_message("ERROR", "server", f"Cleanup error: {str(e)}"))
            print(f"[CLEANUP] Erreur: {e}")


def _perform_cleanup():
    """
    Effectue le nettoyage des agents inactifs.
    Toutes les opérations DB passent par run_async() car db.* est async.
    """
    current_time      = time.time()
    agents_to_offline = []
    agents_to_lost    = []

    # ── Analyse tous les agents en mémoire ────────────────────
    for agent_id, agent in list(storage.agents.items()):
        last_seen = agent.get("last_seen", current_time)
        elapsed   = current_time - last_seen

        # Timeout court → marquer offline
        if elapsed > AGENT_TIMEOUT and agent.get("status") != "offline":
            agents_to_offline.append((agent_id, elapsed))

        # Timeout long → marquer lost + supprimer de la mémoire
        if elapsed > CLEANUP_THRESHOLD:
            agents_to_lost.append((agent_id, elapsed))

    # ── Traite les agents offline ─────────────────────────────
    for agent_id, elapsed in agents_to_offline:
        # Mémoire — sync, instantané
        storage.agents[agent_id]["status"] = "offline"

        # DB — run_async car db.* est async
        run_async(db.set_agent_status(agent_id, "offline"))
        run_async(db.log_agent_event(agent_id, "offline", f"inactif depuis {elapsed:.0f}s"))

        print(f"[CLEANUP] Agent {agent_id} marqué offline ({elapsed:.0f}s)")

    # ── Traite les agents lost ────────────────────────────────
    for agent_id, elapsed in agents_to_lost:
        # DB — run_async car db.* est async
        run_async(db.set_agent_status(agent_id, "lost"))
        run_async(db.log_agent_event(agent_id, "cleanup", "retiré de la mémoire"))

        # Mémoire — sync
        storage.remove_agent_memory(agent_id)

        print(f"[CLEANUP] Agent {agent_id} supprimé mémoire ({elapsed:.0f}s)")

    # ── Log global si changements ─────────────────────────────
    if agents_to_offline or agents_to_lost:
        run_async(db.log_message(
            "INFO", "server",
            f"Cleanup: {len(agents_to_offline)} offline, {len(agents_to_lost)} lost"
        ))