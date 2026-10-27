"""Cache mémoire et helpers pour état runtime des agents/tâches/sessions."""

# ============================================================
#  server/storage.py — Stockage mémoire rapide
#  Rôle        : Cache mémoire pour accès rapide + tokens actifs
#  Importé par : routes.agent, routes.operator, cleanup.py, main.py
#  Dépend de   : config.py (AGENT_TIMEOUT), database.py (pour sync)
#
#  CORRECTION : toutes les fonctions qui appellent db.* sont async
# ============================================================

import time
from typing import Dict, List, Optional
from config import AGENT_TIMEOUT, SESSION_TIMEOUT
import database as db

# ── Dictionnaires mémoire ─────────────────────────────────────
agents:        Dict[str, dict] = {}   # {agent_id: agent_dict}
tasks:         Dict[str, list] = {}   # {agent_id: [{task_id, command}]}
results:       Dict[str, dict] = {}   # {agent_id: last_result_dict}
active_tokens: Dict[str, dict] = {}   # {token: {operator_name, created_at}}


class StorageError(Exception):
    """Exception spécifique au module storage."""


# ============================================================
#  AGENTS — lecture mémoire (sync, rapide)
# ============================================================

def get_agent_status(agent_id: str) -> str:
    """
    Détermine le statut temps réel d'un agent depuis la mémoire.
    Pas de DB → 0.001ms. Appelée à chaque requête.
    """
    if agent_id not in agents:
        return "unknown"
    last_seen = agents[agent_id].get("last_seen", 0)
    elapsed   = time.time() - last_seen
    return "online" if elapsed < AGENT_TIMEOUT else "offline"


def get_pending_count(agent_id: str) -> int:
    """Nombre de tâches en attente pour un agent (lecture mémoire)."""
    return len(tasks.get(agent_id, []))


def register_agent_memory(agent_id: str, agent_data: dict):
    """Enregistre un agent en mémoire."""
    agents[agent_id] = agent_data


def remove_agent_memory(agent_id: str):
    """Supprime un agent de la mémoire (appelé par cleanup)."""
    agents.pop(agent_id, None)
    tasks.pop(agent_id,  None)
    results.pop(agent_id, None)


def get_agent_info(agent_id: str) -> Optional[dict]:
    """Récupère les infos d'un agent depuis la mémoire."""
    return agents.get(agent_id)


def get_all_agents_info() -> List[dict]:
    """Tous les agents avec statut temps réel (lecture mémoire)."""
    result = []
    for agent_id, agent in agents.items():
        info            = agent.copy()
        info["status"]  = get_agent_status(agent_id)
        info["pending"] = get_pending_count(agent_id)
        result.append(info)
    return result


def get_all_online_agents() -> List[dict]:
    """Liste uniquement les agents online (lecture mémoire)."""
    online = []
    for agent_id, agent in agents.items():
        if get_agent_status(agent_id) == "online":
            agent_copy            = agent.copy()
            agent_copy["pending"] = get_pending_count(agent_id)
            online.append(agent_copy)
    return online


# ============================================================
#  AGENTS — écriture mémoire + DB (async car db.* est async)
# ============================================================

async def update_agent_last_seen(agent_id: str):
    """
    Met à jour last_seen en mémoire ET en DB.
    async → db.update_agent_last_seen_db() est async.
    Appelée à chaque poll — critique pour détection online/offline.
    """
    if agent_id in agents:
        agents[agent_id]["last_seen"] = time.time()   # mémoire : instantané
        await db.update_agent_last_seen_db(agent_id)  # DB : await non bloquant


async def sync_agent_from_db(agent_id: str):
    """
    Synchronise un agent depuis la DB vers la mémoire.
    async → db.get_agent_by_id() est async.
    Utilisé quand un agent poll mais n'est plus en mémoire (redémarrage serveur).
    """
    agent = await db.get_agent_by_id(agent_id)   # await ← async
    if agent:
        agents[agent_id] = {
            "id":            agent["id"],
            "hostname":      agent["hostname"],
            "username":      agent["username"],
            "os":            agent["os"],
            "registered_at": agent["registered_at"],
            "last_seen":     agent["last_seen"],
            "status":        agent["status"]
        }


# ============================================================
#  TASKS — lecture/écriture mémoire (sync, rapide)
# ============================================================

def add_task_to_memory(agent_id: str, task_id: str, command: str,
                       module: str = 'shell', file_data: str = '', filename: str = '',
                       technique: str = ''):
    """Ajoute une tâche dans la file mémoire de l'agent."""
    tasks.setdefault(agent_id, []).append({
        "task_id":   task_id,
        "command":   command,
        "module":    module,
        "file_data": file_data,
        "filename":  filename,
        "technique": technique,
    })


def pop_task_for_agent(agent_id: str) -> Optional[dict]:
    """
    Récupère et retire la première tâche de la file (FIFO).
    Retourne None si aucune tâche.
    """
    if agent_id not in tasks or not tasks[agent_id]:
        return None
    return tasks[agent_id].pop(0)


# ============================================================
#  RESULTS — lecture/écriture mémoire (sync)
# ============================================================

def store_result(agent_id: str, result: dict):
    """Stocke le dernier résultat d'un agent en mémoire."""
    results[agent_id] = result


def get_last_result(agent_id: str) -> Optional[dict]:
    """Récupère le dernier résultat d'un agent depuis la mémoire."""
    return results.get(agent_id)


# ============================================================
#  TOKENS / SESSIONS — async car db.get_session() est async
# ============================================================

async def is_token_valid(token: str) -> bool:
    """
    Vérifie si un token est valide et non expiré.
    async → db.get_session() est async.
    Vérifie d'abord le cache mémoire (0.001ms) puis la DB si absent.
    """
    # ── Vérification cache mémoire ────────────────────────────
    if token in active_tokens:
        session = active_tokens[token]
        elapsed = time.time() - session.get("created_at", 0)
        if elapsed < SESSION_TIMEOUT:
            return True
        # Token expiré → nettoie le cache
        active_tokens.pop(token, None)
        return False

    # ── Vérification DB si pas en cache ──────────────────────
    session = await db.get_session(token)   # await ← async
    if session and session.get("is_active"):
        # Remet en cache pour les prochaines requêtes
        active_tokens[token] = {
            "operator_name": session["operator_name"],
            "created_at":    session["created_at"]
        }
        return True

    return False


async def get_token_operator(token: str) -> Optional[str]:
    """
    Récupère le nom d'opérateur associé à un token.
    async → db.get_session() est async.
    """
    if token in active_tokens:
        return active_tokens[token].get("operator_name")

    session = await db.get_session(token)   # await ← async
    if session:
        return session.get("operator_name")
    return None


def add_active_token(token: str, session_dict: dict):
    """Ajoute un token au cache mémoire (sync — pas de DB)."""
    active_tokens[token] = session_dict


async def remove_active_token(token: str):
    """
    Retire un token du cache ET marque la session inactive en DB.
    async → db.close_session() est async.
    """
    active_tokens.pop(token, None)           # mémoire : instantané
    await db.close_session(token)            # DB : await non bloquant