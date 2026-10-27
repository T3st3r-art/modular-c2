/*
 * ============================================================
 *  apc_loader.h - Loader APC Injection (QueueUserAPC)
 *
 *  Technique : APC Injection via QueueUserAPC sur un thread cible.
 *  L'objectif est de fournir une technique d'exécution alternative
 *  au sein du moteur d'exécution multi-technique.
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Juillet 2026
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#ifndef APC_LOADER_H
#define APC_LOADER_H

#include "platform.h"
#include "execution_engine.h"

module_result_t apc_loader_execute(
    const unsigned char *payload_bytes,
    size_t               payload_size,
    const unsigned char *args,
    size_t               args_len
);

#endif /* APC_LOADER_H */
