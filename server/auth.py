# ============================================================
#  server/auth.py — Authentification et middleware
#  Rôle        : Vérification tokens, logging des requêtes
#  Importé par : routes.operator (dépendance FastAPI)
#  Dépend de   : storage.py (is_token_valid), database.py (log_message)
# ============================================================

from fastapi import HTTPException, Header, Request
import storage
import database as db


async def verify_token(session_token: str = Header(..., description="Token de session")) -> dict:
    """
    Dépendance FastAPI — injectée dans toutes les routes opérateur protégées.
    Vérifie que le token est valide et actif.
    Retourne le dict session si valide, lève HTTPException 401 sinon.
    """
    if not session_token:
        raise HTTPException(status_code=401, detail="Token manquant")

    # CORRECTION 1 : await manquant — is_token_valid est async dans storage.py
    if not await storage.is_token_valid(session_token):
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")

    # CORRECTION 2 : await manquant — get_token_operator est async dans storage.py
    operator_name = await storage.get_token_operator(session_token)

    return {
        "token":         session_token,
        "operator_name": operator_name
    }


def get_current_operator(token_data: dict) -> str:
    """Extrait le nom d'opérateur des données de token vérifié."""
    return token_data.get("operator_name", "unknown")


async def log_request_middleware(request: Request, call_next):
    """
    Middleware pour logger toutes les requêtes entrantes.
    À intégrer dans main.py si nécessaire.
    """
    import time
    start_time = time.time()   # CORRECTION 3 : __import__("time") → import time propre

    path = request.url.path

    if path.startswith("/agent"):
        source = "agent"
    elif path.startswith("/operator"):
        source = "operator"
    else:
        source = "server"

    details = ""
    if "/agent/" in path:
        parts = path.split("/")
        if len(parts) >= 3:
            details = f"agent:{parts[2]}"

    response = await call_next(request)

    duration = time.time() - start_time
    message  = f"{request.method} {path} → {response.status_code} ({duration:.3f}s) {details}"
    level    = "INFO" if response.status_code < 400 else "WARNING"

    # CORRECTION 4 : await manquant — log_message est async dans database.py
    await db.log_message(level, source, message)

    return response