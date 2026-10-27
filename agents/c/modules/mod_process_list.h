/*
 * ============================================================
 *  modules/mod_process_list.h — Interface du module process_list
 *
 *  Rôle : Déclare la fonction d'entrée du module d'énumération
 *         des processus en cours d'exécution.
 *
 *  Windows : CreateToolhelp32Snapshot (Toolhelp API) — aucun
 *            appel système, pas de fenêtre, pas de process enfant.
 *  Linux   : Lecture de /proc (pseudo-filesystem noyau) — aucun
 *            fork() ni popen().
 *
 *  Sortie  : Tableau JSON dans ctx->output
 *            [{"pid":N,"name":"...","path":"..."},...]
 * ============================================================
 */
#ifndef MOD_PROCESS_LIST_H
#define MOD_PROCESS_LIST_H

#include "module.h"

/**
 * Énumère les processus en cours d'exécution et produit un
 * tableau JSON dans ctx->output.
 * Retourne 1 si au moins un processus a été listé, 0 sinon.
 */
int mod_process_list_exec(ModuleContext *ctx);

#endif /* MOD_PROCESS_LIST_H */
