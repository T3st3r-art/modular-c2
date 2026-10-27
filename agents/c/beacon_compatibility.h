/*
 * ============================================================
 *  beacon_compatibility.h - API Beacon pour les modules BOF
 *
 *  Role : Implementations locales des fonctions Beacon normalement
 *         fournies par Cobalt Strike. Permet d'executer des BOFs
 *         standard sans dependance a Cobalt Strike.
 *
 *  Principe :
 *    - Le COFF loader appelle beacon_reset_output() avant le BOF
 *    - Le BOF appelle BeaconPrintf/BeaconOutput pour ecrire sa sortie
 *    - Apres execution, le loader lit beacon_get_output() pour recuperer
 *      les donnees et les transmettre au serveur C2
 *
 *  Fonctions implementees :
 *    Sortie    : BeaconPrintf, BeaconOutput
 *    Arguments : BeaconDataParse, BeaconDataExtract, BeaconDataInt,
 *                BeaconDataShort, BeaconDataLength
 *    Format    : BeaconFormatAlloc, BeaconFormatReset, BeaconFormatFree,
 *                BeaconFormatAppend, BeaconFormatPrintf,
 *                BeaconFormatToString, BeaconFormatInt
 *    Utilitaires : BeaconIsAdmin, BeaconIsInSession
 *
 *  Inclus par : coff_loader.c, beacon_compatibility.c
 *  NE PAS inclure dans les modules BOF - utiliser modules/bof/beacon.h
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#ifndef BEACON_COMPATIBILITY_H
#define BEACON_COMPATIBILITY_H

#include "platform.h"
#include <stdarg.h>

/* ?? Constantes de type de callback (compatibilite CS) ????? */
#define CALLBACK_OUTPUT       0x00  /* Sortie standard UTF-8      */
#define CALLBACK_OUTPUT_OEM   0x1e  /* Sortie OEM (Windows CP)    */
#define CALLBACK_OUTPUT_UTF8  0x20  /* Sortie UTF-8 explicite     */
#define CALLBACK_ERROR        0x0d  /* Message d'erreur           */

/* ============================================================
 *  BUFFER DE SORTIE GLOBAL
 *
 *  Accumulateur de toutes les donnees produites par un BOF.
 *  Reinitialise avant chaque BOF, lu apres execution.
 * ============================================================ */
typedef struct {
    char  *buffer;    /* Donnees accumulees (malloc + realloc automatique) */
    size_t length;    /* Nombre d'octets ecrits (hors '\0' final)          */
    size_t capacity;  /* Capacite allouee                                  */
} beacon_output_t;

/** Accede au buffer global de sortie. */
beacon_output_t *beacon_get_output(void);

/** Reinitialise le buffer avant un nouveau BOF. */
void beacon_reset_output(void);

/* ============================================================
 *  FONCTIONS BEACON - SORTIE DE DONNEES
 * ============================================================ */

/**
 * Formate et ajoute une chaine au buffer de sortie.
 * type : CALLBACK_OUTPUT, CALLBACK_ERROR, etc.
 */
void BeaconPrintf(int type, const char *fmt, ...);

/**
 * Ajoute des donnees brutes au buffer de sortie.
 * type : type de callback (generalement CALLBACK_OUTPUT)
 * data : donnees binaires ou texte
 * len  : nombre d'octets
 */
void BeaconOutput(int type, const char *data, int len);

/* ============================================================
 *  FONCTIONS BEACON - PARSING DES ARGUMENTS
 *
 *  Format des arguments (pack/unpack style CS BOF) :
 *    Chaque argument est precede de 4 bytes little-endian (sa taille).
 *    Les entiers sont directement 4 bytes LE, short = 2 bytes LE.
 * ============================================================ */
typedef struct {
    char *original;  /* Pointeur debut du buffer d'origine    */
    char *buffer;    /* Pointeur courant (avance a la lecture) */
    int   length;    /* Octets restants a lire                 */
    int   size;      /* Taille totale du buffer d'origine      */
} datap;

/** Initialise le parser sur un buffer d'arguments. */
void  BeaconDataParse(datap *parser, char *buffer, int size);

/**
 * Extrait un blob (4 bytes taille + donnees).
 * *size recoit la taille extraite.
 * Retourne un pointeur dans le buffer (pas de copie).
 */
char *BeaconDataExtract(datap *parser, int *size);

/** Extrait un entier 32 bits little-endian. */
int   BeaconDataInt(datap *parser);

/** Extrait un entier 16 bits little-endian. */
short BeaconDataShort(datap *parser);

/** Retourne le nombre d'octets restants dans le parser. */
int   BeaconDataLength(datap *parser);

/* ============================================================
 *  FONCTIONS BEACON - FORMATAGE DES RESULTATS
 *
 *  Permet a un BOF de construire une reponse structuree
 *  avant de l'envoyer via BeaconOutput.
 * ============================================================ */
typedef struct {
    char *original;  /* Debut du buffer alloue */
    char *buffer;    /* Position d'ecriture     */
    int   length;    /* Octets ecrits           */
    int   size;      /* Capacite totale         */
} formatp;

/** Alloue un buffer de formatage de taille maxsz. */
void  BeaconFormatAlloc(formatp *format, int maxsz);

/** Remet le curseur d'ecriture au debut sans liberer. */
void  BeaconFormatReset(formatp *format);

/** Libere le buffer de formatage. */
void  BeaconFormatFree(formatp *format);

/** Ajoute len bytes bruts au buffer. */
void  BeaconFormatAppend(formatp *format, const char *data, int len);

/** Formate via printf et ajoute au buffer. */
void  BeaconFormatPrintf(formatp *format, const char *fmt, ...);

/**
 * Retourne le buffer comme chaine.
 * *size recoit le nombre d'octets.
 */
char *BeaconFormatToString(formatp *format, int *size);

/** Ajoute un entier 32 bits little-endian au buffer. */
void  BeaconFormatInt(formatp *format, int value);

/* ============================================================
 *  FONCTIONS BEACON - UTILITAIRES
 * ============================================================ */

/** Retourne 1 si l'agent tourne en tant qu'admin/root. */
int  BeaconIsAdmin(void);

/** Retourne 1 (agent toujours "en session" dans ce contexte). */
int  BeaconIsInSession(void);

/* Stubs pour compatibilite avec BOFs existants */
void *BeaconGetSpawnTo(int x86, char *buffer, int length);
int   BeaconUseToken(void *token);
void  BeaconRevertToken(void);

/* ============================================================
 *  RESOLUTION DES SYMBOLES BEACON
 *
 *  Appelee par le COFF loader pour resoudre les symboles
 *  qui ne suivent pas la convention LIB$Func (ex: BeaconPrintf).
 *
 *  @param name : nom du symbole (avec ou sans __imp_ prefixe)
 *  @return : adresse de la fonction locale, ou NULL si inconnu
 * ============================================================ */
void *beacon_resolve_symbol(const char *name);

#endif /* BEACON_COMPATIBILITY_H */
