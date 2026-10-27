/*
 * ============================================================
 *  shellcode_loader.h — Chargeur de shellcode brut (T1059)
 *
 *  Technique 3 : sRDI / Shellcode in-process
 *  MITRE ATT&CK : T1059 (Command and Script Interpreter)
 *                 T1620 (Reflective Code Loading — variante raw)
 *
 *  Format d'entrée : raw bytes (.bin) — aucun en-tête PE/COFF
 *  Sortie          : module_result_t identique aux autres techniques
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#ifndef SHELLCODE_LOADER_H
#define SHELLCODE_LOADER_H

#include "execution_engine.h"

/*
 * Exécute un shellcode brut dans le processus agent.
 *
 * @param sc_bytes  Bytes bruts du shellcode (pas d'en-tête)
 * @param sc_size   Taille en bytes
 * @param args      Arguments BeaconData (passés comme pointeur au thread)
 * @param args_len  Taille des arguments
 *
 * @return module_result_t — appeler free_module_result() après usage.
 */
module_result_t shellcode_execute(
    const unsigned char *sc_bytes, size_t sc_size,
    const unsigned char *args,     size_t args_len
);

#endif /* SHELLCODE_LOADER_H */
