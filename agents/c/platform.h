/*
 * ============================================================
 *  platform.h - Abstraction cross-platform
 *
 *  Role : Centralise TOUS les includes et macros conditionnels
 *         Windows / Linux. Chaque .c commence par cet include.
 *
 *  Apres cet include :
 *    - PLATFORM_WINDOWS ou PLATFORM_LINUX est defini
 *    - Tous les headers systeme sont disponibles
 *    - Les includes std (stdio, stdlib, string, time) suivent
 * ============================================================
 */
#ifndef PLATFORM_H
#define PLATFORM_H

/* ?? Detection plateforme ????????????????????????????????????
 * Priorite :
 *   1. Flag explicite -DPLATFORM_LINUX  (cross-compilation)
 *   2. Flag explicite -DPLATFORM_WINDOWS
 *   3. Auto-detection via _WIN32 (compilation native)        */
#if defined(PLATFORM_LINUX)
    /* Linux - includes systeme */
    #include <unistd.h>
    #include <sys/utsname.h>   /* uname() - version noyau Linux               */
    #include <sys/types.h>
    #include <sys/wait.h>      /* waitpid()                                   */
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>     /* inet_pton / inet_ntop                       */
    #include <poll.h>          /* poll() - lecture non bloquante              */
    #include <pwd.h>           /* getpwuid() - nom utilisateur                */
    #include <signal.h>        /* kill() / SIGTERM / SIGKILL                  */
    #include <sys/stat.h>      /* stat() / S_ISDIR - detection dossier upload */
    #include <curl/curl.h>     /* libcurl - HTTP Linux uniquement             */

    extern char **environ;     /* Environnement herite pour execve()          */

#elif defined(PLATFORM_WINDOWS) || defined(_WIN32)
    #ifndef PLATFORM_WINDOWS
        #define PLATFORM_WINDOWS 1
    #endif

    #include <winsock2.h>   /* DOIT etre avant windows.h - evite les conflits */
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <winhttp.h>    /* HTTP natif Windows - remplace libcurl           */
    #include <lmcons.h>     /* UNLEN - longueur max nom utilisateur Windows    */

#else
    /* Auto-detection : ni Windows ni Linux explicite > Linux par defaut */
    #define PLATFORM_LINUX 1

    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <poll.h>
    #include <pwd.h>
    #include <signal.h>
    #include <sys/stat.h>
    #include <curl/curl.h>

    extern char **environ;
#endif

/* ?? Includes standards communs (toutes plateformes) ??????? */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#endif /* PLATFORM_H */
