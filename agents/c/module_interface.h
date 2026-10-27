/*
 * ============================================================
 *  module_interface.h - Interface standard des modules dynamiques
 *
 *  Role : Definit les signatures de fonctions d'entree selon le
 *         format du module (BOF, DLL, shellcode, source).
 *         Inclus par les LOADERS, pas par les modules eux-memes.
 *
 *  Convention des noms d'entree par format :
 *    BOF (.o)        > "go"       (convention Cobalt Strike)
 *    DLL (.dll)      > "Execute"  (convention custom)
 *    Shellcode (.bin)> debut du blob (pas de nom)
 *    Source (.c)     > "execute"  (convention custom)
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#ifndef MODULE_INTERFACE_H
#define MODULE_INTERFACE_H

/* Noms des fonctions d'entree selon le format */
#define BOF_ENTRY_FUNC  "go"       /* Convention Cobalt Strike BOF  */
#define DLL_ENTRY_FUNC  "Execute"  /* Convention DLL custom         */
#define SRC_ENTRY_FUNC  "execute"  /* Convention compilation source */

/*
 * Signature d'un module BOF.
 * args     : arguments packes (format BeaconDataParse)
 * args_len : taille en bytes
 * Le module retourne void et communique via BeaconPrintf/BeaconOutput.
 */
typedef void (*bof_entry_func_t)(char *args, int args_len);

/*
 * Signature d'un module DLL (Technique 2 - futur).
 * Retourne 0 si succes.
 */
typedef int (*dll_entry_func_t)(unsigned char *args, int args_len,
                                 void *callback);

#endif /* MODULE_INTERFACE_H */
