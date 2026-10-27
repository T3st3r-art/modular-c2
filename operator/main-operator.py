# ============================================================
#  operator/main.py — Console interactive Prompt Toolkit
#  Rôle        : Boucle principale avec autocomplétion et historique
#  Importé par : exécution directe (python -m operator.main)
#  Dépend de   : prompt_toolkit, commands.py, display.py
# ============================================================

import sys
import threading
import time
from pathlib import Path
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style

from commands import CommandHandler
from display import print_banner


# Style personnalisé pour la console
CUSTOM_STYLE = Style.from_dict({
    'prompt': '#00aaaa bold',      # Cyan bold pour le prompt
    'completion-menu': 'bg:#004444 #ffffff',  # Fond bleu foncé, texte blanc
    'completion-menu.completion': 'bg:#004444 #ffffff',
    'completion-menu.completion.current': 'bg:#00aaaa #000000 bold',  # Sélection cyan
})


class OperatorConsole:
    """Console interactive professionnelle pour opérateur C2."""
    
    def __init__(self, server_url: str):
        self.handler = CommandHandler(server_url)
        # Persistent history file in user's home directory
        history_file = Path.home() / ".c2_operator_history"
        self.history = FileHistory(str(history_file))
        self.completer = None
        self.session = None
        self.running = True
        self.refresh_thread = None
        
        self._setup_session()

    # ── Définition de l'arbre de complétion ───────────────────
    @staticmethod
    def _build_completer(agent_ids: list = None):
        """
        Construit un NestedCompleter hiérarchique.
        agent_ids : liste des IDs agents pour compléter 'use', 'info', etc.
        """
        ids = {aid: None for aid in (agent_ids or [])}

        techniques = {
            '-t': {
                'rdll': None, 'rundll32': None,
                'wpr':  None, 'wermgr':   None,
                'apc':  None, 'apcinject': None,
                'bof':  None,            
            }
        }
        modules = {
            'sysinfo':    techniques, 'screenshot': techniques,
            'shell':      techniques, 'fileops':    techniques,
            'process':    techniques, 'download':   techniques,
            'upload':     techniques, 'hello_bof':  techniques,
            'enum':       techniques, 'paint':       techniques,
              # Modules d'énumération Active Directory
            'adcomputers':  techniques,
            'adusers':      techniques,
            'adgroups':     techniques,
            'adgpo':        techniques,
            'adspn':        techniques,
            'adpreauth':    techniques,
            'adou':         techniques,
            'adpwdpolicy':   techniques,
            'admaq':        techniques,
        }

        return NestedCompleter.from_nested_dict({
            # Session
            'login':    None,
            'logout':   None,
            'help':     None,
            'exit':     None,
            'quit':     None,
            # Agents
            'list':     None,
            'use':      ids,
            'back':     None,
            'info':     ids,
            # Commandes rapides
            'send':     None,
            'sysinfo':  ids,
            'screenshot': ids,
            'ps':       ids,
            'kill':     ids,
            'upload':   None,
            'download': None,
            'loot':     {**ids, 'all': None},
            # Modules dynamiques
            'module':   modules,
            # Énumération rapide (BOF)
            'enum': {
                'all': None, 'whoami': None, 'getuid': None,
                'hostname': None, 'domain': None, 'getpid': None,
                'getintegrity': None, 'drives': None, 'uptime': None,
                **{aid: {
                    'all': None, 'whoami': None, 'getuid': None,
                    'hostname': None, 'domain': None, 'getpid': None,
                    'getintegrity': None, 'drives': None, 'uptime': None,
                } for aid in (agent_ids or [])},
            },
            # Tunnel SOCKS5
            'tunnel': {
                'start': {'--socks5': {':1080': None, ':1081': None, ':8080': None}},
                'list':  None,
                'show':  ids,
                'stop':  ids,
            },
            # Résultats
            'results':  {'all': None},
            'result':   None,
            'history':  {'all': None},
            'events':   ids,
            'sessions': None,
            'stats':    None,
        })

    def _setup_session(self):
        """Configure la session Prompt Toolkit."""
        self.completer = self._build_completer()
        
        self.session = PromptSession(
            history=self.history,
            auto_suggest=AutoSuggestFromHistory(),
            style=CUSTOM_STYLE,
            complete_while_typing=True
        )
    
    def _update_completer(self):
        """Met à jour l'autocomplétion avec les agents disponibles."""
        try:
            import requests
            if self.handler.token:
                resp = requests.get(
                    f"{self.handler.server_url}/operator/agents",
                    headers={"session-token": self.handler.token},
                    timeout=2
                )
                if resp.status_code == 200:
                    agents = [a["id"] for a in resp.json().get("agents", [])]
                    self.completer = self._build_completer(agents)
        except Exception:
            pass
    
    def _start_refresh_thread(self):
        """Démarre le thread de rafraîchissement du prompt."""
        def refresh_loop():
            while self.running:
                time.sleep(30)  # Rafraîchit toutes les 30s
                if self.running:
                    self._update_completer()
        
        self.refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self.refresh_thread.start()
    
    def run(self):
        """Boucle principale de la console."""
        print_banner()
        
        server_url = "http://127.0.0.1:8000"
        if len(sys.argv) > 1:
            server_url = sys.argv[1]
        
        print(f"[i] Connexion au serveur: {server_url}")
        print("[i] Tapez 'login <operator_name>' pour vous connecter")
        print()
        
        self._start_refresh_thread()
        
        while self.running:
            try:
                # Met à jour le prompt dynamique
                prompt_text = self.handler.get_prompt()
                
                # Lecture avec autocomplétion
                line = self.session.prompt(
                    prompt_text,
                    completer=self.completer,
                    complete_while_typing=True
                )
                
                # Exécute la commande
                should_continue = self.handler.handle(line)
                if not should_continue:
                    self.running = False
                    
            except KeyboardInterrupt:
                print("\n[!] Interruption (Ctrl+C)")
                continue
            except EOFError:
                print("\n[i] Fin de fichier (Ctrl+D)")
                self.running = False
            except Exception as e:
                print(f"\n[✗] Erreur inattendue: {e}")
        
        print("[i] Au revoir!")


def main():
    """Point d'entrée."""
    server_url = "http://127.0.0.1:8000"
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    
    console = OperatorConsole(server_url)
    console.run()


if __name__ == "__main__":
    main()