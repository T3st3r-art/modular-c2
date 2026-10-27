/*
 * ============================================================
 *  shell.h - Interface du shell persistant cross-platform
 *
 *  Role : Demarrer et maintenir un shell en arriere-plan,
 *         executer des commandes et recuperer leur sortie.
 *
 *  Windows : powershell.exe -Command - (pas d'echo, sortie propre)
 *  Linux   : /bin/bash --norc --noprofile (PS1='' TERM=dumb)
 *
 *  Depend de : platform.h, utils.h (pour clean_output, sleep_ms)
 * ============================================================
 */
#ifndef SHELL_H
#define SHELL_H

#include "platform.h"
#include "utils.h"

/* ============================================================
 *  STRUCTURE
 * ============================================================ */

/**
 * Shell persistant - maintenu vivant entre les commandes.
 * Les handles/fds varient selon la plateforme.
 */
typedef struct {
    char shell_type[16];    /* "powershell" ou "bash"                     */
    int  alive;             /* 1 = actif, 0 = arrete / redemarrage requis */

#ifdef PLATFORM_WINDOWS
    HANDLE           hStdinWrite;   /* Pipe stdin  > shell                */
    HANDLE           hStdoutRead;   /* Pipe stdout < shell                */
    PROCESS_INFORMATION pi;         /* Handles du processus PowerShell    */
#else
    int   fd_stdin_write;   /* Descripteur d'ecriture stdin du shell      */
    int   fd_stdout_read;   /* Descripteur de lecture stdout du shell     */
    pid_t pid;              /* PID du processus bash                      */
#endif
} PersistentShell;


/* ============================================================
 *  LECTURE AVEC TIMEOUT (fonctions internes, declarees ici)
 * ============================================================ */

#ifdef PLATFORM_LINUX
/**
 * Lit une ligne depuis un fd avec timeout en millisecondes.
 * Utilise poll() pour eviter tout blocage.
 * Retourne le nombre d'octets lus, ou -1 si timeout/erreur.
 */
int readline_timeout(int fd, char *buf, size_t buf_size, int timeout_ms);
#else
/**
 * Lit une ligne depuis un HANDLE Windows avec timeout.
 * Utilise PeekNamedPipe pour eviter tout blocage.
 * Retourne le nombre d'octets lus, ou -1 si timeout/erreur.
 */
int readline_timeout_win(HANDLE hRead, char *buf, size_t buf_size, int timeout_ms);
#endif


/* ============================================================
 *  API PUBLIQUE DU SHELL
 * ============================================================ */

/**
 * Demarre le shell persistant et vide la banniere de demarrage.
 * Retourne 1 si succes, 0 si echec.
 */
int shell_start(PersistentShell *sh);

/**
 * Verifie si le processus shell est encore actif.
 * Retourne 1 si vivant, 0 si mort.
 */
int shell_is_alive(PersistentShell *sh);

/**
 * Arrete le shell courant et en demarre un nouveau.
 * Retourne 1 si le redemarrage reussit, 0 sinon.
 */
int shell_restart(PersistentShell *sh);

/**
 * Envoie une chaine brute dans le stdin du shell.
 * Retourne 1 si succes, 0 si erreur.
 */
int shell_write(PersistentShell *sh, const char *data);

/**
 * Execute une commande dans le shell persistant et collecte sa sortie.
 *
 * Mecanisme sentinel :
 *   1. Envoie la commande + un marqueur unique dans stdin
 *   2. Lit stdout jusqu'a trouver le marqueur
 *   3. Nettoie la sortie (ANSI, prompts, sentinel)
 *
 * Retourne 1 si succes ou timeout, 0 si le shell est mort.
 */
int shell_run(PersistentShell *sh, const char *command,
              const char *task_id, char *out, size_t out_size);

#endif /* SHELL_H */
