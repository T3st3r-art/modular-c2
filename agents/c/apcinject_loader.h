/*
 *  apcinject_loader.h - Loader APC Injection cross-process
 *
 *  Technique : APC Injection (T1055.004) via QueueUserAPC sur
 *  les threads existants d'un processus distant.
 *  Le payload est un shellcode brut position-independent.
 *
 * ============================================================
 */
#ifndef APCINJECT_LOADER_H
#define APCINJECT_LOADER_H

#include "platform.h"
#include "execution_engine.h"

module_result_t apcinject_loader_execute(
    const unsigned char *payload_bytes,
    size_t               payload_size,
    const unsigned char *args,
    size_t               args_len
);

#endif 
