/*
 * ============================================================
 *  modules/mod_process_list.c — Module d'énumération des processus
 *
 *  Rôle : Lister tous les processus actifs de la machine cible
 *         et retourner un tableau JSON formaté dans ctx->output.
 *
 *  Implémentation :
 *    Windows : CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
 *              → API Toolhelp32 intégrée au kernel32, aucune DLL
 *                externe, aucune fenêtre, aucun shell enfant.
 *              → QueryFullProcessImageNameA pour le chemin complet
 *                (Vista+, kernel32.dll — lié par défaut).
 *
 *    Linux   : Lecture de /proc/{pid}/comm (nom court) et
 *              readlink("/proc/{pid}/exe") pour le chemin.
 *              Aucun fork() ni popen() — lecture pure filesystem.
 *
 *  Format de sortie (ctx->output) :
 *    [
 *    {"pid":4,"name":"System","path":""},
 *    {"pid":768,"name":"svchost.exe","path":"C:\\Windows\\System32\\svchost.exe"},
 *    ...
 *    ]
 *
 *  Limite : ~1 300 processus dans le buffer de 128 KB. Suffisant
 *           pour tout système de production.
 * ============================================================
 */
#include "../platform.h"
#include "../config.h"
#include "../utils.h"
#include "module.h"

/* ── Inclusion conditionnelle Toolhelp32 (Windows uniquement) ─ */
#ifdef PLATFORM_WINDOWS
#  include <tlhelp32.h>
#endif

/* ── Inclusion conditionnelle /proc parsing (Linux uniquement) ─ */
#ifdef PLATFORM_LINUX
#  include <dirent.h>
#endif


/* ============================================================
 *  UTILITAIRE : Échappement JSON minimal
 *
 *  Écrit src dans dst en échappant les caractères spéciaux JSON :
 *    \  →  \\
 *    "  →  \"
 *    \r \n \t → supprimés (noms de processus ne les contiennent pas)
 *  dst est terminé par '\0'. Retourne le nombre de bytes écrits.
 * ============================================================ */
static int json_escape(const char *src, char *dst, int dst_max) {
    int i = 0, o = 0;
    while (src[i] && o < dst_max - 2) {
        unsigned char c = (unsigned char)src[i++];
        if (c == '\\') {
            if (o + 2 >= dst_max - 1) break;
            dst[o++] = '\\'; dst[o++] = '\\';
        } else if (c == '"') {
            if (o + 2 >= dst_max - 1) break;
            dst[o++] = '\\'; dst[o++] = '"';
        } else if (c >= 0x20) {   /* Garde les caractères imprimables */
            dst[o++] = (char)c;
        }
    }
    dst[o] = '\0';
    return o;
}


/* ============================================================
 *  IMPLÉMENTATION WINDOWS
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

int mod_process_list_exec(ModuleContext *ctx) {
    char  *out      = ctx->output;
    size_t out_max  = ctx->output_size;
    int    pos      = 0;
    int    count    = 0;

    /* Ouvre un snapshot de tous les processus actifs.
     * TH32CS_SNAPPROCESS : capture la table de processus noyau.
     * Paramètre th32ProcessID = 0 → snapshot global (tous PIDs). */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        snprintf(out, out_max,
                 "[{\"error\":\"CreateToolhelp32Snapshot failed: %lu\"}]",
                 (unsigned long)GetLastError());
        return 0;
    }

    /* Ouvre le tableau JSON */
    pos += snprintf(out + pos, (int)out_max - pos, "[\n");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);   /* OBLIGATOIRE avant Process32First */

    BOOL ok = Process32First(snap, &pe);
    while (ok) {
        /* ── Récupère le chemin complet de l'exécutable ────────
         * On ouvre le processus avec PROCESS_QUERY_LIMITED_INFORMATION
         * (Vista+), qui ne nécessite pas de privilèges élevés sur la
         * plupart des processus utilisateur.
         * Pour les processus système (pid 0, 4) ou protégés, on obtient
         * ERROR_ACCESS_DENIED → path reste vide, ce qui est normal.   */
        char path[MAX_PATH] = "";
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD sz = (DWORD)sizeof(path);
            /* QueryFullProcessImageNameA : retourne le chemin NT complet
             * (plus fiable que GetModuleFileNameEx, ne nécessite pas
             * PROCESS_VM_READ ni psapi). Disponible depuis Vista. */
            QueryFullProcessImageNameA(hProc, 0, path, &sz);
            CloseHandle(hProc);
        }

        /* ── Échappement JSON des champs texte ───────────────── */
        char name_e[64]  = "";
        char path_e[520] = "";
        json_escape(pe.szExeFile, name_e, (int)sizeof(name_e));
        json_escape(path,         path_e, (int)sizeof(path_e));

        /* ── Calcul de la place restante avant d'écrire ─────────
         * Réserve 10 octets pour "]}" de fermeture du tableau.   */
        int remaining = (int)out_max - pos - 10;
        if (remaining < 80) break;  /* Buffer plein → arrêt propre */

        pos += snprintf(out + pos, remaining,
            "{\"pid\":%lu,\"name\":\"%s\",\"path\":\"%s\"},\n",
            (unsigned long)pe.th32ProcessID, name_e, path_e);
        count++;

        ok = Process32Next(snap, &pe);
    }

    CloseHandle(snap);

    /* Supprime la dernière virgule trailing si au moins un processus */
    if (count > 0 && pos >= 2) {
        /* Recule sur ",\n" → remplace par "\n" */
        if (out[pos-2] == ',' && out[pos-1] == '\n') {
            out[pos-2] = '\n';
            pos--;
        }
    }

    /* Ferme le tableau JSON */
    snprintf(out + pos, (int)out_max - pos, "]");
    return (count > 0) ? 1 : 0;
}

#endif /* PLATFORM_WINDOWS */


/* ============================================================
 *  IMPLÉMENTATION LINUX
 * ============================================================ */
#ifdef PLATFORM_LINUX

/**
 * Lit le nom court d'un processus depuis /proc/{pid}/comm.
 * comm contient le nom de l'exécutable tronqué à 15 caractères.
 * Retourne 1 si lu, 0 sinon.
 */
static int read_proc_comm(pid_t pid, char *name, size_t name_sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(name, (int)name_sz, f)) { fclose(f); return 0; }
    fclose(f);
    /* Supprime le \n final de comm */
    size_t l = strlen(name);
    if (l > 0 && name[l-1] == '\n') name[l-1] = '\0';
    return 1;
}

/**
 * Résout le chemin complet via readlink("/proc/{pid}/exe").
 * Retourne 1 si résolu, 0 si le processus est un thread noyau
 * ou si l'accès est refusé.
 */
static int read_proc_exe(pid_t pid, char *exepath, size_t sz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(link, exepath, (int)sz - 1);
    if (n <= 0) { exepath[0] = '\0'; return 0; }
    exepath[n] = '\0';
    return 1;
}

int mod_process_list_exec(ModuleContext *ctx) {
    char  *out     = ctx->output;
    size_t out_max = ctx->output_size;
    int    pos     = 0;
    int    count   = 0;

    /* Ouvre /proc — pseudo-filesystem exposé par le noyau Linux.
     * Chaque sous-dossier numérique correspond à un PID actif.  */
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        snprintf(out, out_max, "[{\"error\":\"opendir(/proc) failed\"}]");
        return 0;
    }

    pos += snprintf(out + pos, (int)out_max - pos, "[\n");

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Filtre : ne garde que les entrées entièrement numériques */
        const char *d = entry->d_name;
        int is_pid = 1;
        for (int k = 0; d[k]; k++) {
            if (d[k] < '0' || d[k] > '9') { is_pid = 0; break; }
        }
        if (!is_pid || d[0] == '\0') continue;

        pid_t pid = (pid_t)atoi(d);

        char name[64]    = "";
        char exepath[512] = "";

        /* Nom : /proc/{pid}/comm — toujours lisible même sans privs */
        read_proc_comm(pid, name, sizeof(name));

        /* Chemin : /proc/{pid}/exe — peut échouer pour kernel threads */
        read_proc_exe(pid, exepath, sizeof(exepath));

        if (name[0] == '\0') continue;  /* PID disparu entre readdir et fopen */

        /* Échappement JSON */
        char name_e[80]   = "";
        char path_e[1040] = "";
        json_escape(name,    name_e, (int)sizeof(name_e));
        json_escape(exepath, path_e, (int)sizeof(path_e));

        /* Vérifie la place disponible (réserve 10 pour "]\0") */
        int remaining = (int)out_max - pos - 10;
        if (remaining < 80) break;

        pos += snprintf(out + pos, remaining,
            "{\"pid\":%d,\"name\":\"%s\",\"path\":\"%s\"},\n",
            (int)pid, name_e, path_e);
        count++;
    }

    closedir(proc_dir);

    /* Supprime la virgule trailing */
    if (count > 0 && pos >= 2) {
        if (out[pos-2] == ',' && out[pos-1] == '\n') {
            out[pos-2] = '\n';
            pos--;
        }
    }

    snprintf(out + pos, (int)out_max - pos, "]");
    return (count > 0) ? 1 : 0;
}

#endif /* PLATFORM_LINUX */
