/*
 * mod_hello_bof.c — Module de diagnostic BOF minimal
 *
 * Teste uniquement BeaconPrintf sans aucun appel Windows API.
 * Permet d'isoler si le problème est dans le loader ou dans les modules.
 *
 * Résultat attendu : "Hello from BOF! Loader OK\n"
 */
#include "beacon.h"

void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_OUTPUT, "Hello from BOF! Loader OK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Deuxieme appel OK\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Valeur: %d\n", 42);
}
