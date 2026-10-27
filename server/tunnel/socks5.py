# ============================================================
#  server/tunnel/socks5.py — Serveur SOCKS5 (RFC 1928)
#
#  Chaque connexion SOCKS5 cliente lance un Socks5Handler.
#  Les données sont relayées via TunnelManager ↔ agent HTTP.
#
#  Flux :
#    curl → Socks5Handler → TunnelConnection.agent_commands
#    Agent poll → commands → envoie au vrai serveur
#    Agent → POST /tunnel/data → TunnelConnection.agent_responses
#    Socks5Handler ← agent_responses → curl
# ============================================================

import socket
import struct
import threading
import uuid
import time
import base64
import queue
import logging

from tunnel.manager import tunnel_manager, TunnelConnection

logger = logging.getLogger(__name__)

SOCKS5_VER    = 5
SOCKS5_NOAUTH = 0


def _socks5_reply(rep: int) -> bytes:
    """Construit une réponse SOCKS5 (VER=5, REP, RSV=0, ATYP=IPv4, ADDR=0, PORT=0)."""
    return bytes([5, rep, 0, 1, 0, 0, 0, 0, 0, 0])


class Socks5Handler(threading.Thread):
    """
    Gère une connexion SOCKS5 cliente dans son propre thread.
    Cycle : handshake → CONNECT → relay (2 sous-threads).
    """

    def __init__(self, client_sock: socket.socket, agent_id: str):
        super().__init__(daemon=True)
        self.client_sock = client_sock
        self.agent_id    = agent_id
        self.tunnel_id   = uuid.uuid4().hex[:16]

    # ── Handshake ─────────────────────────────────────────────

    def _handshake(self) -> bool:
        data = self.client_sock.recv(257)
        if not data or data[0] != SOCKS5_VER:
            return False
        self.client_sock.send(bytes([SOCKS5_VER, SOCKS5_NOAUTH]))
        return True

    def _parse_connect(self):
        """Parse la requête CONNECT — retourne (host, port) ou None."""
        header = self.client_sock.recv(4)
        if len(header) < 4:
            return None
        ver, cmd, _, atyp = header
        if ver != SOCKS5_VER or cmd != 1:
            self.client_sock.send(_socks5_reply(7))  # command not supported
            return None

        if atyp == 1:       # IPv4
            raw  = self.client_sock.recv(4)
            host = socket.inet_ntoa(raw)
        elif atyp == 3:     # domaine
            n    = self.client_sock.recv(1)[0]
            host = self.client_sock.recv(n).decode(errors="replace")
        elif atyp == 4:     # IPv6
            raw  = self.client_sock.recv(16)
            host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            self.client_sock.send(_socks5_reply(8))  # atyp not supported
            return None

        port = struct.unpack("!H", self.client_sock.recv(2))[0]
        return host, port

    # ── Relay ─────────────────────────────────────────────────

    def _relay(self, conn: TunnelConnection):
        """
        Deux sous-threads :
          client_to_agent  : lit du client SOCKS5 → queued pour l'agent
          agent_to_client  : lit la queue → écrit vers le client SOCKS5
        """
        stop = threading.Event()

        def client_to_agent():
            self.client_sock.settimeout(1.0)
            while not stop.is_set():
                try:
                    data = self.client_sock.recv(32768)
                    if not data:
                        conn.agent_commands.put({
                            "type": "CLOSE", "tunnel_id": self.tunnel_id
                        })
                        stop.set()
                        return
                    conn.agent_commands.put({
                        "type":      "DATA",
                        "tunnel_id": self.tunnel_id,
                        "data":      base64.b64encode(data).decode()
                    })
                    conn.last_active = time.time()
                except socket.timeout:
                    pass
                except OSError:
                    stop.set()
                    return

        def agent_to_client():
            while not stop.is_set():
                try:
                    resp = conn.agent_responses.get(timeout=1.0)
                    status = resp.get("status", "")
                    if status in ("closed", "error"):
                        stop.set()
                        return
                    raw_b64 = resp.get("data", "")
                    if raw_b64:
                        raw = base64.b64decode(raw_b64)
                        try:
                            self.client_sock.sendall(raw)
                        except OSError:
                            stop.set()
                            return
                    conn.last_active = time.time()
                except queue.Empty:
                    if time.time() - conn.last_active > 60:
                        conn.agent_commands.put({
                            "type": "CLOSE", "tunnel_id": self.tunnel_id
                        })
                        stop.set()
                        return
                except OSError:
                    stop.set()
                    return

        t1 = threading.Thread(target=client_to_agent, daemon=True)
        t2 = threading.Thread(target=agent_to_client, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    # ── Point d'entrée du thread ───────────────────────────────

    def run(self):
        try:
            if not _handshake_ok(self):
                return

            result = self._parse_connect()
            if not result:
                return
            host, port = result

            logger.info(f"[SOCKS5] CONNECT {host}:{port} via agent {self.agent_id} (tid={self.tunnel_id})")

            conn = TunnelConnection(self.tunnel_id)
            tunnel_manager.add_connection(self.agent_id, conn)

            # Envoyer CONNECT à l'agent
            conn.agent_commands.put({
                "type":      "CONNECT",
                "tunnel_id": self.tunnel_id,
                "host":      host,
                "port":      port
            })

            # Attendre confirmation de l'agent (max 15s)
            try:
                resp = conn.agent_responses.get(timeout=15)
            except queue.Empty:
                self.client_sock.send(_socks5_reply(4))  # host unreachable
                tunnel_manager.remove_connection(self.agent_id, self.tunnel_id)
                return

            if resp.get("status") != "connected":
                self.client_sock.send(_socks5_reply(5))  # connection refused
                tunnel_manager.remove_connection(self.agent_id, self.tunnel_id)
                return

            # Succès SOCKS5
            self.client_sock.send(_socks5_reply(0))
            conn.state = "open"
            logger.info(f"[SOCKS5] Tunnel ouvert : {host}:{port} ← agent {self.agent_id}")

            self._relay(conn)

        except Exception as e:
            logger.error(f"[SOCKS5] Erreur handler : {e}")
        finally:
            try:
                self.client_sock.close()
            except OSError:
                pass
            tunnel_manager.remove_connection(self.agent_id, self.tunnel_id)
            logger.debug(f"[SOCKS5] Handler terminé (tid={self.tunnel_id})")


def _handshake_ok(h: Socks5Handler) -> bool:
    return h._handshake()


# ── Serveur SOCKS5 ────────────────────────────────────────────

class Socks5Server(threading.Thread):
    """
    Thread serveur — écoute sur host:port, spawne un Socks5Handler
    par connexion cliente.  L'agent actif est configurable à chaud.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 1080):
        super().__init__(daemon=True, name=f"socks5-{port}")
        self.host       = host
        self.port       = port
        self._agent_id  = None
        self._running   = False
        self._sock      = None

    def set_agent(self, agent_id: str):
        self._agent_id = agent_id

    def clear_agent(self):
        self._agent_id = None

    def run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.host, self.port))
        except OSError as e:
            logger.error(f"[SOCKS5] Impossible de binder :{self.port} — {e}")
            return
        self._sock.listen(64)
        self._sock.settimeout(1.0)
        self._running = True
        logger.info(f"[SOCKS5] Écoute sur {self.host}:{self.port}")

        while self._running:
            try:
                client_sock, addr = self._sock.accept()
                if not self._agent_id:
                    client_sock.close()
                    continue
                Socks5Handler(client_sock, self._agent_id).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"[SOCKS5] Erreur serveur : {e}")

        try:
            self._sock.close()
        except OSError:
            pass
        logger.info(f"[SOCKS5] Serveur :{self.port} arrêté")

    def stop(self):
        self._running = False


# ── Registry des serveurs SOCKS5 (port → serveur) ────────────

_servers: dict = {}   # port → Socks5Server
_srv_lock = threading.Lock()


def get_or_create_server(port: int) -> Socks5Server:
    with _srv_lock:
        if port not in _servers or not _servers[port].is_alive():
            srv = Socks5Server(port=port)
            _servers[port] = srv
            srv.start()
        return _servers[port]


def stop_server_for_agent(agent_id: str):
    with _srv_lock:
        for srv in _servers.values():
            if srv._agent_id == agent_id:
                srv.clear_agent()
                break
