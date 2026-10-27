/*
 * ============================================================
 *  modules/mod_shell.c — Module shell
 *
 *  Rôle : Exécuter une commande dans le shell persistant
 *         et retourner sa sortie nettoyée.
 *
 *  Note : shell_run() retourne 0 si le shell est mort, mais
 *         même une commande introuvable est un succès du module
 *         (le shell a bien fonctionné). On force success = 1.
 * ============================================================
 */
#include "../platform.h"
#include "../config.h"
#include "../utils.h"
#include "../shell.h"
#include "module.h"

/**
 * Exécute ctx->command dans le shell persistant ctx->shell.
 * La sortie est écrite dans ctx->output.
 * Retourne toujours 1 (success) — les erreurs de commande
 * sont dans la sortie, pas dans le code de retour.
 */
int mod_shell_exec(ModuleContext *ctx) {
    int ok = shell_run(ctx->shell, ctx->command, ctx->task_id,
                       ctx->output, ctx->output_size);
    if (!ok && ctx->output[0] == '\0')
        strncpy(ctx->output, "[ERREUR] Exécution échouée", ctx->output_size - 1);
    /* Le shell lui-même a fonctionné même si la commande a échoué */
    return 1;
}
