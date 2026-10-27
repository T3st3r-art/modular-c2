/*
 * ============================================================
 *  modules/mod_sysinfo.c — Module sysinfo
 *
 *  Rôle : Construire un rapport système détaillé.
 *
 *  Données collectées :
 *    OS, hostname, username, architecture, CWD, PID, IP locale
 *
 *  IP locale : trick UDP vers 8.8.8.8:80 sans paquet envoyé —
 *              récupère l'IP source de l'interface de routage.
 * ============================================================
 */
#include "../platform.h"
#include "../config.h"
#include "../utils.h"
#include "module.h"

/**
 * Construit un rapport système complet dans ctx->output.
 * Utilise ctx->sysinfo (hostname, username, os) collecté au démarrage.
 * Ajoute dynamiquement : arch, CWD, PID, IP locale.
 * Retourne toujours 1.
 */
int mod_sysinfo_exec(ModuleContext *ctx) {
    const SystemInfo *si = ctx->sysinfo;
    char cwd[512] = "?";
    char ip[64]   = "?";
    char arch[32] = "?";

    /* ── Répertoire courant ─────────────────────────────────── */
#ifdef PLATFORM_WINDOWS
    GetCurrentDirectoryA(sizeof(cwd), cwd);
#else
    if (!getcwd(cwd, sizeof(cwd))) strncpy(cwd, "?", sizeof(cwd) - 1);
#endif

    /* ── Architecture ──────────────────────────────────────── */
    strncpy(arch, sizeof(void*) == 8 ? "x86_64" : "x86", sizeof(arch) - 1);

    /* ── IP locale via socket trick ────────────────────────────
     * Ouvre un socket UDP (sans envoyer de paquet) et connecte-le
     * vers 8.8.8.8:80. Le noyau sélectionne l'interface de routage
     * et getsockname() retourne l'IP locale correspondante.         */
#ifdef PLATFORM_WINDOWS
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port   = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &sin.sin_addr);
        if (connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0) {
            struct sockaddr_in local;
            int len = sizeof(local);
            getsockname(s, (struct sockaddr*)&local, &len);
            inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
        }
        closesocket(s);
    }
#else
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port   = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &sin.sin_addr);
        if (connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0) {
            struct sockaddr_in local;
            socklen_t len = sizeof(local);
            getsockname(s, (struct sockaddr*)&local, &len);
            inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
        }
        close(s);
    }
#endif

    snprintf(ctx->output, ctx->output_size,
        "Hostname   : %s\n"
        "Username   : %s\n"
        "OS         : %s\n"
        "Arch       : %s\n"
        "CWD        : %s\n"
#ifdef PLATFORM_WINDOWS
        "PID        : %lu\n"
#else
        "PID        : %d\n"
#endif
        "IP locale  : %s",
        si->hostname, si->username, si->os, arch, cwd,
#ifdef PLATFORM_WINDOWS
        (unsigned long)GetCurrentProcessId(),
#else
        (int)getpid(),
#endif
        ip
    );
    return 1;
}