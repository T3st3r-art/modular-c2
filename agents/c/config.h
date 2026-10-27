/*
 * ============================================================
 *  config.h - Configuration de l'agent C2
 *
 *  Role : Toutes les constantes et parametres hardcodes
 *         dans le binaire. Modifiez ce fichier avant chaque
 *         compilation pour adapter l'agent a l'engagement.
 *
 *  Aucune dependance - inclus en premier dans chaque .c
 * ============================================================
 */
#ifndef CONFIG_H
#define CONFIG_H

/* ?? Liste des serveurs C2 (style Cobalt Strike / Havoc) ??????
 * Definie UNE SEULE FOIS dans core.c - declaree extern ici
 * pour eviter le warning "defined but not used" dans chaque .c  */
extern const char *C2_SERVER_LIST[];

/* ?? Timing et intervalles ?????????????????????????????????? */
#define POLL_INTERVAL_MS   3000   /* Intervalle de polling de base (ms)    */
#define JITTER_PERCENT     40     /* ?40% aleatoire sur l'intervalle       */
#define HTTP_TIMEOUT_SEC   10     /* Timeout reseau par requete (secondes) */
#define CMD_TIMEOUT_MS     30000  /* Timeout max execution commande (30s)  */

/* ?? Tailles de buffer ?????????????????????????????????????? */
#define MAX_OUTPUT_SIZE    131072  /* 128 KB - resultat max renvoye        */
#define LINE_BUF_SIZE      4096   /* Taille d'une ligne de sortie shell    */

/* ?? Backoff exponentiel (reconnexion serveur) ?????????????? */
/* Defini UNE SEULE FOIS dans utils.c - declare extern ici     */
extern const int BACKOFF_DELAYS[];
#define BACKOFF_COUNT 5

#endif /* CONFIG_H */
