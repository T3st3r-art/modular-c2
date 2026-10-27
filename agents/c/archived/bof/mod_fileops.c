/*
 * ============================================================
 *  modules/bof/mod_fileops.c — Opérations fichiers au format BOF
 *
 *  Commandes supportées (passées comme premier argument) :
 *    ls   <path>         — liste un répertoire
 *    cat  <path>         — affiche un fichier texte
 *    rm   <path>         — supprime un fichier
 *    mkdir <path>        — crée un répertoire
 *    pwd                 — répertoire courant
 *
 *  Format des arguments (BeaconDataParse) :
 *    [4 bytes: cmd_len][cmd]  ex: "ls"
 *    [4 bytes: path_len][path] ex: "C:\Users"
 *
 *  Compilation BOF :
 *    x86_64-w64-mingw32-gcc -c -DBOF_MODE -o fileops.x64.o mod_fileops.c
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "beacon.h"

/* ── Déclarations Windows API (BOF mode uniquement) ──────────
 * En RDLL mode, windows.h fournit déjà ces déclarations.     */
#ifndef RDLL_MODE
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentDirectoryA(DWORD, LPSTR);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$DeleteFileA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError(void);
#endif /* !RDLL_MODE */

#ifndef INVALID_HANDLE_VALUE
#  define INVALID_HANDLE_VALUE  ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef INVALID_FILE_ATTRS
#  define INVALID_FILE_ATTRS    0xFFFFFFFF
#endif
#ifndef FILE_ATTRIBUTE_DIRECTORY
#  define FILE_ATTRIBUTE_DIRECTORY 0x10
#endif
#ifndef GENERIC_READ
#  define GENERIC_READ          0x80000000
#endif
#ifndef OPEN_EXISTING
#  define OPEN_EXISTING         3
#endif
#ifndef FILE_SHARE_READ
#  define FILE_SHARE_READ       0x00000001
#endif

#ifndef RDLL_MODE
/* FILETIME doit être défini AVANT _WIN32_FIND_DATA qui l'utilise */
typedef struct { DWORD dwLowDateTime; DWORD dwHighDateTime; } FILETIME;

/* Structure WIN32_FIND_DATA locale (en BOF mode, pas de windows.h) */
typedef struct {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
    DWORD    dwReserved0;
    DWORD    dwReserved1;
    CHAR     cFileName[260];
    CHAR     cAlternateFileName[14];
} _WIN32_FIND_DATA;
#endif /* !RDLL_MODE */


/* ── Utilitaires internes ─────────────────────────────────── */

/* Concatène deux chaînes dans out (taille out_sz) */
static void str_concat(char *out, size_t out_sz, const char *a, const char *b) {
    int i = 0, j = 0;
    while (a[i] && (size_t)i < out_sz - 1) out[i++] = a[j++];
    j = 0;
    while (b[j] && (size_t)i < out_sz - 1) out[i++] = b[j++];
    out[i] = '\0';
}

static int str_eq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}


/* ── Commande : ls ────────────────────────────────────────── */

static void cmd_ls(const char *path) {
    char pattern[512];
    str_concat(pattern, sizeof(pattern), path, "\\*");

    _WIN32_FIND_DATA ffd;
    HANDLE hFind = KERNEL32$FindFirstFileA(pattern, (LPWIN32_FIND_DATAA)&ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] ls: répertoire inaccessible '%s'\n", path);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Contenu de : %s\n", path);
    BeaconPrintf(CALLBACK_OUTPUT, "%-10s  %-12s  %s\n", "Type", "Taille", "Nom");
    BeaconPrintf(CALLBACK_OUTPUT, "%-10s  %-12s  %s\n", "----------", "------------", "---");

    int count = 0;
    do {
        const char *type = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "<DIR>" : "<FILE>";
        unsigned long long size_bytes =
            ((unsigned long long)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            BeaconPrintf(CALLBACK_OUTPUT, "%-10s  %-12s  %s\n",
                         type, "-", ffd.cFileName);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "%-10s  %-12llu  %s\n",
                         type, size_bytes, ffd.cFileName);
        }
        count++;
    } while (KERNEL32$FindNextFileA(hFind, (LPWIN32_FIND_DATAA)&ffd));

    KERNEL32$FindClose(hFind);
    BeaconPrintf(CALLBACK_OUTPUT, "\n%d entrée(s)\n", count);
}


/* ── Commande : cat ───────────────────────────────────────── */

static void cmd_cat(const char *path) {
    HANDLE hFile = KERNEL32$CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] cat: impossible d'ouvrir '%s' (err: %lu)\n",
                     path, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    char   buf[4096];
    DWORD  bytes_read = 0;
    DWORD  total      = 0;

    while (KERNEL32$ReadFile(hFile, buf, sizeof(buf) - 1, &bytes_read, NULL)
           && bytes_read > 0) {
        buf[bytes_read] = '\0';
        BeaconOutput(CALLBACK_OUTPUT, buf, (int)bytes_read);
        total += bytes_read;
    }

    KERNEL32$CloseHandle(hFile);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[%lu bytes lus]\n", (unsigned long)total);
}


/* ── Commande : rm ────────────────────────────────────────── */

static void cmd_rm(const char *path) {
    if (KERNEL32$DeleteFileA(path)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[OK] Fichier supprimé : %s\n", path);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] rm: impossible de supprimer '%s' (err: %lu)\n",
                     path, (unsigned long)KERNEL32$GetLastError());
    }
}


/* ── Commande : mkdir ─────────────────────────────────────── */

static void cmd_mkdir(const char *path) {
    if (KERNEL32$CreateDirectoryA(path, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[OK] Répertoire créé : %s\n", path);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] mkdir: '%s' (err: %lu)\n",
                     path, (unsigned long)KERNEL32$GetLastError());
    }
}


/* ── Commande : pwd ───────────────────────────────────────── */

static void cmd_pwd(void) {
    char cwd[512] = {0};
    KERNEL32$GetCurrentDirectoryA(sizeof(cwd), cwd);
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", cwd);
}


/* ── Fonction d'entrée BOF ────────────────────────────────── */

/*
 * Supporte deux formats d'appel :
 *  A) Agent minimal (pack_args) : une seule valeur "cmd path"
 *     ex: "ls C:\Users"  →  cmd_buf="ls", path_buf="C:\Users"
 *  B) Format Beacon classique  : deux valeurs séparées
 *     [4][ls][4][C:\Users]
 */
void go(char *args, int args_len) {
    datap  parser;
    char  *first    = NULL;
    char  *second   = NULL;
    int    first_len  = 0;
    int    second_len = 0;

    BeaconDataParse(&parser, args, args_len);
    first  = BeaconDataExtract(&parser, &first_len);
    second = BeaconDataExtract(&parser, &second_len);

    if (!first || first_len == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[ERREUR] fileops: commande manquante\n"
            "Commandes : ls <path> | cat <path> | rm <path> | mkdir <path> | pwd\n");
        return;
    }

    char cmd_buf[32]   = {0};
    char path_buf[512] = {0};
    int fl = first_len < 511 ? first_len : 511;

    if (second && second_len > 0) {
        /* Format B : deux valeurs distinctes */
        int cl = first_len < 31 ? first_len : 31;
        int pl = second_len < 511 ? second_len : 511;
        __builtin_memcpy(cmd_buf,  first,  (size_t)cl);
        __builtin_memcpy(path_buf, second, (size_t)pl);
    } else {
        /* Format A : "cmd path" dans une seule valeur, split sur espace */
        char combined[512] = {0};
        __builtin_memcpy(combined, first, (size_t)fl);

        int i = 0;
        while (combined[i] && combined[i] != ' ' && i < 31) {
            cmd_buf[i] = combined[i];
            i++;
        }
        if (combined[i] == ' ') {
            int j = 0;
            i++;
            while (combined[i] && j < 511) path_buf[j++] = combined[i++];
        }
    }

    /* Dispatch vers la commande */
    if      (str_eq(cmd_buf, "ls"))    cmd_ls(path_buf[0] ? path_buf : ".");
    else if (str_eq(cmd_buf, "cat"))   cmd_cat(path_buf);
    else if (str_eq(cmd_buf, "rm"))    cmd_rm(path_buf);
    else if (str_eq(cmd_buf, "mkdir")) cmd_mkdir(path_buf);
    else if (str_eq(cmd_buf, "pwd"))   cmd_pwd();
    else {
        BeaconPrintf(CALLBACK_ERROR,
            "[ERREUR] fileops: commande inconnue '%s'\n"
            "Commandes : ls | cat | rm | mkdir | pwd\n", cmd_buf);
    }
}