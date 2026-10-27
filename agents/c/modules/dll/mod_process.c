/*
 * ============================================================
 *  modules/bof/mod_process.c — Liste des processus (BOF/RDLL)
 *
 *  Enumère tous les processus via CreateToolhelp32Snapshot et
 *  retourne PID, PPID, nombre de threads et nom de l'exécutable.
 *
 *  Compilation BOF :
 *    x86_64-w64-mingw32-gcc -c -DBOF_MODE -o process.x64.o mod_process.c
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "beacon.h"

/* En RDLL mode, tlhelp32.h fournit PROCESSENTRY32 et les constantes */
#ifdef RDLL_MODE
#  include <tlhelp32.h>
#endif

/* ── Déclarations BOF mode ────────────────────────────────── */
#ifndef RDLL_MODE

#define TH32CS_SNAPPROCESS  0x00000002

typedef struct {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    CHAR      szExeFile[260];
} PROCESSENTRY32;
typedef PROCESSENTRY32 *LPPROCESSENTRY32;

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

#endif /* !RDLL_MODE */

#ifndef INVALID_HANDLE_VALUE
#  define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif


/* ── Fonction d'entrée BOF ────────────────────────────────── */

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    PROCESSENTRY32 pe;
    __builtin_memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[ERREUR] CreateToolhelp32Snapshot échoué\n");
        return;
    }

    /* En-tête du tableau */
    BeaconPrintf(CALLBACK_OUTPUT,
        "%-8s %-8s %-5s %s\n"
        "%-8s %-8s %-5s %s\n",
        "PID",      "PPID",     "THRD", "NOM",
        "--------", "--------", "-----", "----");

    int count = 0;

    if (KERNEL32$Process32First(snap, &pe)) {
        do {
            BeaconPrintf(CALLBACK_OUTPUT,
                "%-8lu %-8lu %-5lu %s\n",
                (unsigned long)pe.th32ProcessID,
                (unsigned long)pe.th32ParentProcessID,
                (unsigned long)pe.cntThreads,
                pe.szExeFile);
            count++;
        } while (KERNEL32$Process32Next(snap, &pe));
    }

    KERNEL32$CloseHandle(snap);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[OK] %d processus\n", count);
}
