/*
 * ============================================================
 *  coff_loader.h - Chargeur COFF/BOF (Beacon Object File)
 *
 *  Permet l'execution de fichiers objet COFF x64 (.o) compiles
 *  avec GCC/MinGW en mode BOF (-DBOF_MODE), compatibles avec
 *  le format Beacon Object File de Cobalt Strike.
 *
 *  Fonctionnement interne (coff_loader.c) :
 *    1. Parser l'en-tete COFF et les sections
 *    2. Allouer chaque section en memoire (VirtualAlloc)
 *    3. Copier les donnees brutes des sections
 *    4. Resoudre les symboles externes :
 *         > API Beacon via beacon_resolve_symbol()
 *         > DFR LIB$Func via LoadLibrary + GetProcAddress
 *         > API Windows standard via DLLs chargees
 *    5. Appliquer les relocalisations AMD64
 *    6. Definir les permissions finales (RX / RW)
 *    7. Appeler le symbole 'go(char *args, int args_len)'
 *    8. Lire le buffer de sortie Beacon
 *    9. Liberer toute la memoire allouee
 *
 *  MITRE ATT&CK : T1620 - Reflective Code Loading (variante COFF)
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Mai 2026
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#ifndef COFF_LOADER_H
#define COFF_LOADER_H

#include "execution_engine.h"

/*
 * Charge et execute un fichier COFF/BOF (.o) en memoire.
 *
 * @param bof_bytes : bytes bruts du fichier .o recu du serveur
 * @param bof_size  : taille en bytes
 * @param args      : arguments packes au format BeaconDataParse
 * @param args_len  : taille des arguments (0 si aucun)
 * @return module_result_t - appeler free_module_result() apres usage
 */
module_result_t coff_loader_execute(
    const unsigned char *bof_bytes, size_t bof_size,
    const unsigned char *args,      size_t args_len
);

#endif /* COFF_LOADER_H */
