/*
 * ============================================================
 *  coff_loader.c - Chargeur COFF/BOF (Beacon Object File)
 *
 *  Flux d'execution :
 *
 *    Agent                         Memoire processus
 *      ?                                 ?
 *      ?? bof_bytes (.o brut)            ?
 *      ?? parser en-tete COFF            ?
 *      ?   ?? sections, symtab, strtab   ?
 *      ?? VirtualAlloc par section ???????  .text (RWX>RX)
 *      ?                                 ?  .data (RW)
 *      ?                                 ?  .rdata (RO)
 *      ?                                 ?  trampolines (RW)
 *      ?? copier donnees des sections    ?
 *      ?? resoudre symboles externes     ?
 *      ?   ?? BeaconXxx > beacon_resolve_symbol()
 *      ?   ?? LIB$Func  > LoadLibrary + GetProcAddress
 *      ?   ?? Func       > GetProcAddress sur DLLs chargees
 *      ?? appliquer relocalisations AMD64?
 *      ?? VirtualProtect (RX sur .text)  ?
 *      ?? trouver symbole 'go'           ?
 *      ?? appeler go(args, args_len)     ?
 *      ?? lire beacon_get_output()       ?
 *      ?? VirtualFree toutes sections   ??
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Mai 2026
 *  Projet  : Framework C2 Modulaire - PFE INPT 2026
 * ============================================================
 */

#include "coff_loader.h"
#include "beacon_compatibility.h"
#include "platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================
 *  IMPLEMENTATION WINDOWS UNIQUEMENT
 * ============================================================ */
#ifdef PLATFORM_WINDOWS

#include <windows.h>

/* ============================================================
 *  STRUCTURES COFF (pack 1 : aucun padding, tailles exactes)
 * ============================================================ */

#pragma pack(push, 1)

/* En-tete principal du fichier COFF */
typedef struct {
    WORD  Machine;                /* 0x8664 = AMD64              */
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;   /* offset absolu dans le fichier */
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;   /* 0 pour les .o                */
    WORD  Characteristics;
} CoffFileHdr;

/* En-tete de section */
typedef struct {
    BYTE  Name[8];                /* nom court (pas forcement '\0') */
    DWORD VirtualSize;            /* aussi PhysicalAddress          */
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;       /* offset des donnees brutes      */
    DWORD PointerToRelocations;   /* offset de la table de reloc    */
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;        /* permissions : EXEC | READ | WRITE */
} CoffSectionHdr;

/* Entree de relocalisation (8 bytes) */
typedef struct {
    DWORD VirtualAddress;         /* offset dans la section         */
    DWORD SymbolTableIndex;       /* index dans la table symboles   */
    WORD  Type;                   /* IMAGE_REL_AMD64_*              */
} CoffReloc;

/* Entree de symbole COFF - exactement 18 bytes */
#define COFF_SYM_SIZE 18

typedef struct {
    union {
        BYTE  ShortName[8];       /* nom si <= 8 chars              */
        struct {
            DWORD Short;          /* si == 0 > offset dans strtab  */
            DWORD Long;           /* offset dans la string table    */
        } Name;
    } N;
    DWORD  Value;                 /* offset dans la section (externe=0) */
    SHORT  SectionNumber;         /* 1-based ; 0=indefini ; -1=absolu   */
    WORD   Type;
    BYTE   StorageClass;          /* 2=EXTERNAL                     */
    BYTE   NumberOfAuxSymbols;    /* records auxiliaires a ignorer  */
} CoffSym;

#pragma pack(pop)

/* ?? Types de relocalisations AMD64 ??????????????????????????? */
#define REL_AMD64_ADDR64   0x0001  /* adresse 64-bit absolue        */
#define REL_AMD64_ADDR32   0x0002  /* adresse 32-bit absolue        */
#define REL_AMD64_ADDR32NB 0x0003  /* RVA 32-bit (relatif a l'image) */
#define REL_AMD64_REL32    0x0004  /* relatif PC 32-bit (offset 4)  */
#define REL_AMD64_REL32_1  0x0005  /* relatif PC 32-bit (offset 5)  */
#define REL_AMD64_REL32_2  0x0006
#define REL_AMD64_REL32_3  0x0007
#define REL_AMD64_REL32_4  0x0008
#define REL_AMD64_REL32_5  0x0009

/* ?? Caracteristiques des sections ???????????????????????????? */
#define SCN_EXEC  0x20000000
#define SCN_READ  0x40000000
#define SCN_WRITE 0x80000000
#define SCN_CODE  0x00000020
#define SCN_BSS   0x00000080

/* ?? Trampolines executables : jmp [rip+0] + adresse ?????????
 *  14 bytes par trampoline :
 *    FF 25 00 00 00 00       = jmp qword ptr [rip+0]
 *    xx xx xx xx xx xx xx xx = adresse reelle de la fonction
 *
 *  Pourquoi du code et non juste des donnees ?
 *  BeaconPrintf/BeaconDataParse sont declares sans __declspec(dllimport),
 *  donc GCC genere un appel DIRECT "E8 rel32" (call rel32).
 *  Le rel32 pointe vers notre trampoline. Le CPU l'execute comme du code.
 *  Un slot DATA serait interprete comme une instruction invalide > crash.
 *  Le jmp [rip+0] saute a l'adresse reelle stockee aux 8 bytes suivants. */
/* ?? Stub ___chkstk_ms - assembleur au niveau fichier ?????????
 *
 *  __attribute__((naked)) est NON GARANTI sur x86-64 GCC :
 *  le compilateur peut inserer un prologue standard (push rbp /
 *  mov rbp,rsp) AVANT notre asm, corrompant la pile de sonde.
 *  L'assembleur fichier (__asm__ global) est la SEULE approche
 *  fiable - aucun wrapping n'est genere.
 *
 *  Convention ___chkstk_ms (non standard, GCC runtime) :
 *    RAX  = nombre de bytes a sonder
 *    RSP  = pointeur de pile au moment du CALL
 *    Apres 2 pushes + call, RSP = RSP_initial - 24 :
 *      [RSP+0]  = RAX sauve (push %rax)
 *      [RSP+8]  = RCX sauve (push %rcx)  [ordre inverse : push rcx push rax]
 *      [RSP+16] = adresse de retour (call trampoline > jmp > ici)
 *    > lea 24(%rsp), %rcx  donne RSP_initial (avant le CALL)  ?
 *
 *  Sonde toutes les pages de [RSP_initial - RAX] a [RSP_initial].
 * ?????????????????????????????????????????????????????????????*/
/* ___chkstk_ms - sonde de pile, file-scope asm (sans prologue GCC)
 *
 *  __attribute__((naked)) n'est pas garanti sur x86-64 : GCC peut
 *  inserer push rbp / mov rbp,rsp avant notre asm > corruption.
 *  Le __asm__ global evite tout wrapping.
 *
 *  Pourquoi une vraie sonde est necessaire pour shell/screenshot :
 *    Shell alloue cmd_line[4096] + buf[4096] = ~8 KB de pile.
 *    Avec seulement "ret" (pas de sonde), sub rsp,8416 saute par-
 *    dessus la guard page a RSP-4096 sans la toucher > la page
 *    n'est pas committee. Le premier acces a RSP-8192 declenche
 *    alors une ACCESS_VIOLATION (pas une guard page exception) car
 *    le mecanisme Windows exige des acces PAGE PAR PAGE en ordre
 *    decroissant. La sonde garantit cet ordre.
 *
 *  Convention ___chkstk_ms :
 *    RAX = bytes a allouer       RCX = temporaire
 *    Tous les registres preserves (sauf flags)
 *    Appele via trampoline JMP > RSP = call_site_RSP - 8 a l'entree
 *    > apres 2 pushes : RSP = call_site_RSP - 24
 *    > lea 24(%rsp), %rcx = call_site_RSP  ?                       */
__asm__(
    ".text\n\t"
    ".align 8\n\t"
    ".globl bof_chkstk_impl\n\t"
    "bof_chkstk_impl:\n\t"
    "    push %rcx\n\t"
    "    push %rax\n\t"
    "    lea  24(%rsp), %rcx\n\t"   /* RCX = RSP avant le CALL  */
    "    cmp  $0x1000, %rax\n\t"
    "    jb   2f\n\t"
    "1:\n\t"
    "    sub  $0x1000, %rcx\n\t"
    "    orl  $0, (%rcx)\n\t"       /* toucher page > guard commit */
    "    sub  $0x1000, %rax\n\t"
    "    cmp  $0x1000, %rax\n\t"
    "    jge  1b\n\t"
    "2:\n\t"
    "    sub  %rax, %rcx\n\t"
    "    orl  $0, (%rcx)\n\t"       /* derniere page partielle    */
    "    pop  %rax\n\t"
    "    pop  %rcx\n\t"
    "    ret\n\t"
);
extern void bof_chkstk_impl(void);

#define MAX_TRAMPOLINES 512
#define TRAMPOLINE_SIZE  14   /* 6 bytes jmp + 8 bytes adresse */

/* ============================================================
 *  CONTEXTE DU LOADER
 *  Toutes les donnees necessaires regroupees en une structure.
 * ============================================================ */
typedef struct {
    const BYTE    *file;              /* buffer brut du .o            */
    size_t         file_size;
    CoffFileHdr   *hdr;               /* pointeur dans le buffer      */
    CoffSectionHdr*sections;          /* tableau des sections         */
    const BYTE    *symtab_raw;        /* table des symboles (raw)     */
    const char    *strtab;            /* string table (apres symtab)  */
    DWORD          strtab_size;
    BYTE          **sec_mem;          /* memoire allouee par section  */
    BYTE           *trampolines;      /* pointeurs de fonctions impo. */
    int             tramp_count;      /* trampolines utilises         */
} CoffCtx;


/* ============================================================
 *  ACCES RAPIDE AUX SYMBOLES
 *  On evite le cast direct car la table n'est pas alignee.
 * ============================================================ */
static void sym_get(const CoffCtx *ctx, DWORD idx, CoffSym *out) {
    memcpy(out, ctx->symtab_raw + (size_t)idx * COFF_SYM_SIZE, COFF_SYM_SIZE);
}

/* Retourne un pointeur sur le nom du symbole (dans le buffer ou strtab).
 * buf/buf_sz : espace pour les noms courts (evite un static). */
static const char *sym_name(const CoffCtx *ctx, const CoffSym *sym,
                              char *buf, size_t buf_sz) {
    if (sym->N.Name.Short == 0) {
        /* Nom long : offset dans la string table */
        DWORD off = sym->N.Name.Long;
        if (ctx->strtab && off < ctx->strtab_size)
            return ctx->strtab + off;
        return "<hors_strtab>";
    }
    /* Nom court : jusqu'a 8 chars, pas forcement null-terminated */
    size_t n = (buf_sz > 9) ? 8 : buf_sz - 1;
    memcpy(buf, sym->N.ShortName, n);
    buf[n] = '\0';
    return buf;
}


/* ============================================================
 *  LISTE DES DLLS DE FALLBACK
 *  Toutes les DLLs dans lesquelles on cherche si la DLL
 *  specifiee par le BOF ne contient pas la fonction.
 * ============================================================ */
static const char *FALLBACK_DLLS[] = {
    "kernel32.dll",  "ntdll.dll",      "advapi32.dll",
    "user32.dll",    "gdi32.dll",      "ws2_32.dll",
    "msvcrt.dll",    "shell32.dll",    "ole32.dll",
    "secur32.dll",   "crypt32.dll",    "winhttp.dll",
    "netapi32.dll",  "iphlpapi.dll",   "shlwapi.dll",
    "winspool.drv",  "version.dll",    "psapi.dll",
    NULL
};

/* ?? Etape 2 : recherche dans tous les fallback_dlls ????????
 *  Parcourt toutes les DLLs de la liste pour trouver func_name.
 *  Utilise quand la DLL prefixee dans DFR ne contient pas la fonction. */
static void *search_fallback_dlls(const char *func_name) {
    for (int i = 0; FALLBACK_DLLS[i]; i++) {
        HMODULE hm = GetModuleHandleA(FALLBACK_DLLS[i]);
        if (!hm) hm = LoadLibraryA(FALLBACK_DLLS[i]);
        if (!hm) continue;
        void *fn = (void *)GetProcAddress(hm, func_name);
        if (fn) {
            printf("[BOF] Fallback : %s < %s\n", func_name, FALLBACK_DLLS[i]);
            return fn;
        }
    }
    return NULL;
}

/* ?? Etape 1 : tentative sur la DLL specifiee ???????????????
 *  Accepte le nom avec ou sans extension (.dll).
 *  Retourne NULL si la DLL n'est pas trouvable ou
 *  si elle ne contient pas la fonction. */
static void *dfr_try_named_dll(const char *dll_stem, const char *func_name) {
    /* Detecter les API-Set virtuelles (api-ms-win-*, ext-ms-win-*)
     * Ces DLLs n'existent pas physiquement - elles sont forwardees
     * par Windows vers la vraie DLL hote.
     * On delegue directement au fallback global. */
    if (_strnicmp(dll_stem, "api-ms-win", 10) == 0 ||
        _strnicmp(dll_stem, "ext-ms-win", 10) == 0) {
        printf("[BOF] API-Set '%s' > recherche globale\n", dll_stem);
        return NULL; /* > fallback */
    }

    char dll_full[72] = {0};
    snprintf(dll_full, sizeof(dll_full), "%s.dll", dll_stem);

    /* Essayer d'abord ce qui est deja charge, puis forcer le chargement */
    HMODULE hm = GetModuleHandleA(dll_full);
    if (!hm) hm = LoadLibraryA(dll_full);
    if (!hm) {
        /* Parfois le stem est deja le nom complet (ex: "winspool.drv") */
        hm = GetModuleHandleA(dll_stem);
        if (!hm) hm = LoadLibraryA(dll_stem);
    }
    if (!hm) return NULL;

    return (void *)GetProcAddress(hm, func_name);
}

/* ============================================================
 *  RESOLUTION DES SYMBOLES EXTERNES - algorithme robuste
 *
 *  Etape 0 : API Beacon (BeaconPrintf, BeaconDataParse, etc.)
 *  Etape 1 : DFR  LIB$Fonction > tentative sur la DLL nommee
 *  Etape 2 : Fallback global   > recherche dans toutes les DLLs
 *            (utilise si LIB erronee, API-Set, ou forward Windows)
 *  Etape 3 : Symbole nu (sans $) > fallback global direct
 * ============================================================ */
static void *resolve_symbol(const char *raw_name) {
    /* Normaliser : retirer __imp_ ou _ */
    const char *name = raw_name;
    if (strncmp(name, "__imp_", 6) == 0) name += 6;
    else if (*name == '_')               name += 1;

    /* ?? Runtime GCC : ___chkstk_ms et variantes ???????????????
     *  Generee pour les fonctions allouant >4096 bytes sur la pile.
     *  Absente de toutes les DLL Windows (libgcc statique uniquement).
     *  On retourne notre stub integre dans le loader.            */
    if (strcmp(name, "__chkstk_ms")  == 0 ||
        strcmp(name, "___chkstk_ms") == 0 ||
        strcmp(name, "__chkstk")     == 0  ||
        strcmp(name, "_alloca")      == 0) {
        printf("[BOF] Runtime GCC : %s > bof_chkstk\n", name);
        return (void *)bof_chkstk_impl;
    }

    /* ?? Etape 0 : API Beacon ????????????????????????????????? */
    void *beacon = beacon_resolve_symbol(name);
    if (beacon) {
        printf("[BOF] Beacon : %s\n", name);
        return beacon;
    }

    /* ?? Etape 1 + 2 : DFR LIB$Fonction ?????????????????????? */
    const char *dollar = strchr(name, '$');
    if (dollar) {
        char dll_stem[64]   = {0};
        char func_name[128] = {0};
        size_t dll_len = (size_t)(dollar - name);
        if (dll_len >= sizeof(dll_stem)) dll_len = sizeof(dll_stem) - 1;
        memcpy(dll_stem, name, dll_len);
        strncpy(func_name, dollar + 1, sizeof(func_name) - 1);

        /* Etape 1 : tentative sur la DLL prefixee par le BOF */
        void *fn = dfr_try_named_dll(dll_stem, func_name);
        if (fn) {
            printf("[BOF] DFR : %s > %p\n", name, fn);
            return fn;
        }

        /* Etape 2 : la DLL etait fausse ou une API-Set
         * > chercher la fonction dans toutes les DLLs connues */
        printf("[BOF] DFR step2 : '%s' absent de '%s', recherche globale\n",
               func_name, dll_stem);
        fn = search_fallback_dlls(func_name);
        if (fn) return fn;

        printf("[BOF] Symbole non resolu : %s\n", name);
        return NULL;
    }

    /* ?? Etape 3 : symbole nu (pas de prefixe LIB$) ??????????? */
    void *fn = search_fallback_dlls(name);
    if (fn) return fn;

    printf("[BOF] Symbole non resolu : %s\n", raw_name);
    return NULL;
}


/* ============================================================
 *  TRAMPOLINES EXECUTABLES
 *
 *  Chaque trampoline est un stub de 14 bytes :
 *    [0..5]  FF 25 00 00 00 00 > jmp qword ptr [rip+0]
 *    [6..13] adresse reelle    > la fonction cible
 *
 *  Utilise pour les appels DIRECTS (E8 rel32) vers des fonctions
 *  externes situees a >2 GB du BOF (BeaconPrintf, etc.).
 *  Le rel32 pointe vers le debut du trampoline (adresse proche).
 *  Le CPU execute le jmp qui saute vers la vraie fonction.
 * ============================================================ */
static BYTE *alloc_trampoline(CoffCtx *ctx, void *fn_ptr) {
    if (ctx->tramp_count >= MAX_TRAMPOLINES) {
        printf("[BOF] Table de trampolines pleine (%d max)\n", MAX_TRAMPOLINES);
        return NULL;
    }

    BYTE *t = ctx->trampolines + (size_t)ctx->tramp_count * TRAMPOLINE_SIZE;

    /* jmp qword ptr [rip+0] */
    t[0] = 0xFF;
    t[1] = 0x25;
    t[2] = 0x00;   /* disp32 = 0 > lit les 8 bytes juste apres */
    t[3] = 0x00;
    t[4] = 0x00;
    t[5] = 0x00;

    /* Adresse reelle de la fonction */
    *(ULONG_PTR *)(t + 6) = (ULONG_PTR)fn_ptr;

    ctx->tramp_count++;
    return t;  /* adresse du DEBUT du stub (code executable) */
}


/* ============================================================
 *  APPLICATION DES RELOCALISATIONS AMD64
 *
 *  Deux types de symboles cibles :
 *
 *  Interne (SectionNumber > 0) :
 *    > adresse = sec_mem[section] + sym.Value
 *    > ADDR64 et REL32 utilisent cette adresse directement.
 *
 *  Externe (SectionNumber == 0, ex: __imp_KERNEL32$GetUserNameA) :
 *    > On resout la vraie adresse de la fonction (fn_direct).
 *    > ADDR64 : ecrire fn_direct directement dans le site de patch.
 *               (le site de patch en .rdata EST le slot d'import ;
 *                `call [rip+offset_vers_slot]` lira fn_direct. ?)
 *    > REL32  : la fonction est dans une DLL systeme (>2 GB).
 *               On alloue un trampoline local (slot = fn_direct),
 *               et on ecrit le delta vers ce slot. ?
 *
 *  Erreur classique a eviter :
 *    ADDR64 externe > trampoline_address > call [rip+offset] lit
 *    l'adresse du slot (DATA), essaie de l'executer > ACCESS VIOLATION.
 * ============================================================ */
static int apply_relocations(CoffCtx *ctx, int sec_idx) {
    CoffSectionHdr *sec = &ctx->sections[sec_idx];
    if (sec->NumberOfRelocations == 0) return 1;
    if (!ctx->sec_mem[sec_idx])        return 1;

    const BYTE *reloc_base = ctx->file + sec->PointerToRelocations;
    BYTE       *sec_data   = ctx->sec_mem[sec_idx];
    char        nbuf[16];

    for (WORD ri = 0; ri < sec->NumberOfRelocations; ri++) {
        CoffReloc reloc;
        memcpy(&reloc, reloc_base + (size_t)ri * sizeof(CoffReloc),
               sizeof(CoffReloc));

        if (reloc.SymbolTableIndex >= ctx->hdr->NumberOfSymbols) {
            printf("[BOF] Index symbole hors limites : %lu\n",
                   (unsigned long)reloc.SymbolTableIndex);
            return 0;
        }

        CoffSym sym;
        sym_get(ctx, reloc.SymbolTableIndex, &sym);
        const char *sname = sym_name(ctx, &sym, nbuf, sizeof(nbuf));

        /* ?? Resolution selon le type de symbole ??????????????? */
        void *fn_direct    = NULL;  /* adresse reelle (externe)  */
        BYTE *fn_indirect  = NULL;  /* trampoline slot (externe) */
        BYTE *internal_tgt = NULL;  /* adresse section (interne) */

        if (sym.SectionNumber > 0) {
            int ts = sym.SectionNumber - 1;
            if (ts < (int)ctx->hdr->NumberOfSections && ctx->sec_mem[ts])
                internal_tgt = ctx->sec_mem[ts] + sym.Value;
        } else if (sym.SectionNumber == 0) {
            fn_direct = resolve_symbol(sname);
            if (!fn_direct) {
                printf("[BOF] Resolution echouee : %s\n", sname);
                return 0;
            }
            /* Trampoline : slot local contenant fn_direct (pour REL32) */
            fn_indirect = alloc_trampoline(ctx, fn_direct);
            if (!fn_indirect) return 0;
        } else {
            continue; /* absolu ou indefini */
        }

        BYTE *patch = sec_data + reloc.VirtualAddress;

        switch (reloc.Type) {

        /* ?? ADDR64 : adresse 64-bit absolue ??????????????????? *
         *                                                        *
         *  Symboles INTERNES (SectionNumber > 0) - ex: strings  *
         *    Les 8 bytes au site de reloc contiennent un ADDEND  *
         *    implicite = offset de la donnee dans sa section.    *
         *    addr_finale = sec_mem[section] + sym.Value + addend *
         *                                                        *
         *  Symboles EXTERNES (SectionNumber == 0) - imports      *
         *    L'addend est 0 > ecrire fn_direct directement.      */
        case REL_AMD64_ADDR64: {
            ULONG_PTR addr;
            if (sym.SectionNumber == 0) {
                /* Externe : adresse directe de la fonction */
                addr = (ULONG_PTR)fn_direct;
            } else if (!internal_tgt) {
                addr = 0;
            } else if (sym.Value == 0) {
                /* Symbole de section (A) : addend = offset dans la section */
                LONG_PTR addend = 0;
                memcpy(&addend, patch, sizeof(LONG_PTR));
                addr = (ULONG_PTR)((BYTE *)internal_tgt + addend);
            } else {
                /* Symbole nomme (B) : sym.Value contient l'offset complet */
                addr = (ULONG_PTR)internal_tgt;
            }
            *(ULONG_PTR *)patch = addr;
            break;
        }

        /* ?? ADDR32 : adresse 32-bit absolue ??????????????????? */
        case REL_AMD64_ADDR32: {
            ULONG_PTR addr;
            if (sym.SectionNumber == 0) {
                addr = (ULONG_PTR)fn_direct;
            } else if (internal_tgt) {
                LONG addend = 0;
                memcpy(&addend, patch, sizeof(LONG));
                addr = (ULONG_PTR)((BYTE *)internal_tgt + addend);
            } else {
                addr = 0;
            }
            *(DWORD *)patch = (DWORD)addr;
            break;
        }

        /* ?? ADDR32NB : RVA 32-bit ????????????????????????????? */
        case REL_AMD64_ADDR32NB: {
            ULONG_PTR base = ctx->sec_mem[0] ? (ULONG_PTR)ctx->sec_mem[0] : 0;
            ULONG_PTR addr;
            if (sym.SectionNumber == 0) {
                addr = (ULONG_PTR)fn_direct;
            } else if (internal_tgt) {
                LONG addend = 0;
                memcpy(&addend, patch, sizeof(LONG));
                addr = (ULONG_PTR)((BYTE *)internal_tgt + addend);
            } else {
                addr = 0;
            }
            *(DWORD *)patch = (DWORD)(addr - base);
            break;
        }

        /* ?? REL32 : adresse relative PC (32-bit) ?????????????? *
         *                                                        *
         *  SYMBOLES INTERNES - deux sous-cas selon sym.Value :  *
         *                                                        *
         *  (A) sym.Value == 0  > symbole de SECTION             *
         *      Utilise pour les references aux donnees statiques *
         *      (strings, constantes) : l'addend au site de reloc *
         *      contient l'offset de la donnee dans sa section.   *
         *      > tgt = sec_mem[s] + addend_implicite      ?     *
         *                                                        *
         *  (B) sym.Value > 0   > symbole NOMME                  *
         *      Utilise pour les appels a des fonctions locales   *
         *      (ex: b64_encode_chunk dans screenshot).           *
         *      sym.Value contient deja l'offset complet dans la  *
         *      section. L'addend initial est -4 (sentinel GCC)   *
         *      ou 0 - il ne doit PAS etre ajoute.               *
         *      > tgt = sec_mem[s] + sym.Value             ?     *
         *                                                        *
         *  SYMBOLES EXTERNES :                                   *
         *    E8   = CALL direct > fn_indirect (jmp stub)         *
         *    FF 15= CALL indirect > fn_indirect+6 (data slot)   */
        case REL_AMD64_REL32:
        case REL_AMD64_REL32_1:
        case REL_AMD64_REL32_2:
        case REL_AMD64_REL32_3:
        case REL_AMD64_REL32_4:
        case REL_AMD64_REL32_5: {
            int N = (int)(reloc.Type - REL_AMD64_REL32);
            BYTE *tgt;

            if (sym.SectionNumber == 0) {
                /* Externe : detecter FF 15 / FF 25 (indirect) ou E8 (direct) */
                BOOL is_indirect = FALSE;
                if (reloc.VirtualAddress >= 2) {
                    BYTE op1 = sec_data[reloc.VirtualAddress - 2];
                    BYTE op2 = sec_data[reloc.VirtualAddress - 1];
                    if (op1 == 0xFF && (op2 == 0x15 || op2 == 0x25))
                        is_indirect = TRUE;
                }
                tgt = is_indirect ? (fn_indirect + 6) : fn_indirect;

            } else if (sym.Value == 0) {
                /* Interne, symbole de section (A) :
                 * L'addend au site de reloc encode l'offset de la cible.
                 * Deux sous-cas selon que la cible est dans la M?ME section
                 * ou une section DIFFERENTE :
                 *
                 * (A1) Meme section - ex: go() appelle b64_encode_chunk
                 *      dans le meme .text :
                 *   addend = b64_offset - (call_site + 4)   < relatif section
                 *   Ce deplacement reste identique une fois les bases absolues
                 *   substituees (sec_base se simplifie).
                 *   > Ecrire addend directement dans patch.
                 *
                 * (A2) Section differente - ex: .text ref > string en .rdata
                 *   addend = string_offset_in_rdata
                 *   tgt = sec_mem[rdata] + addend
                 *   > Formule standard.                                    */
                LONG addend = 0;
                memcpy(&addend, patch, sizeof(LONG));
                int sym_sec = sym.SectionNumber - 1;  /* 1-based > 0-based  */

                if (sym_sec == sec_idx) {
                    /* (A1) Meme section : addend est deja le deplacement final */
                    *(LONG *)patch = addend;
                    break;  /* skip le calcul delta ci-dessous */
                } else {
                    /* (A2) Section differente : appliquer addend a la base  */
                    tgt = internal_tgt ? (internal_tgt + addend) : NULL;
                }

            } else {
                /* Interne, symbole nomme (B) : sym.Value = offset complet,
                 * addend GCC = -4 (sentinel) > NE PAS ajouter              */
                tgt = internal_tgt;   /* = sec_mem[section] + sym.Value     */
            }

            SSIZE_T delta = (SSIZE_T)tgt - (SSIZE_T)(patch + 4 + N);
            if (delta > INT_MAX || delta < INT_MIN) {
                printf("[BOF] REL32 overflow sym=%s (delta=%lld)\n",
                       sname, (long long)delta);
                return 0;
            }
            *(LONG *)patch = (LONG)delta;
            break;
        }

        default:
            printf("[BOF] Type reloc ignore : 0x%x (%s)\n", reloc.Type, sname);
            break;
        }
    }
    return 1;
}


/* ============================================================
 *  POINT D'ENTREE PUBLIC : coff_loader_execute()
 * ============================================================ */
module_result_t coff_loader_execute(
    const unsigned char *bof_bytes, size_t bof_size,
    const unsigned char *args,      size_t args_len)
{
    module_result_t result = {0};
    CoffCtx ctx            = {0};

    printf("[BOF] Chargement COFF %zu bytes\n", bof_size);
    fflush(stdout);

    /* ?? 1. Validation de l'en-tete ?????????????????????????? */
    if (bof_size < sizeof(CoffFileHdr)) {
        result.status    = -1;
        result.error_msg = _strdup("[BOF] Fichier trop petit");
        return result;
    }

    ctx.file      = bof_bytes;
    ctx.file_size = bof_size;
    ctx.hdr       = (CoffFileHdr *)bof_bytes;

    if (ctx.hdr->Machine != 0x8664) {
        char err[128];
        snprintf(err, sizeof(err),
                 "[BOF] Architecture 0x%04x non supportee (attendu 0x8664 AMD64)",
                 ctx.hdr->Machine);
        result.status    = -1;
        result.error_msg = _strdup(err);
        return result;
    }

    printf("[BOF] Sections=%lu Symboles=%lu\n",
           (unsigned long)ctx.hdr->NumberOfSections,
           (unsigned long)ctx.hdr->NumberOfSymbols);
    fflush(stdout);

    /* ?? 2. Localiser sections, table des symboles, strtab ???? */
    ctx.sections = (CoffSectionHdr *)(bof_bytes + sizeof(CoffFileHdr));

    if (ctx.hdr->PointerToSymbolTable &&
        ctx.hdr->NumberOfSymbols > 0) {

        ctx.symtab_raw = bof_bytes + ctx.hdr->PointerToSymbolTable;

        /* String table : immediatement apres la symbol table    */
        const BYTE *st_ptr = ctx.symtab_raw +
            (size_t)ctx.hdr->NumberOfSymbols * COFF_SYM_SIZE;

        if ((size_t)(st_ptr - bof_bytes) + 4 <= bof_size) {
            DWORD st_size;
            memcpy(&st_size, st_ptr, 4);
            ctx.strtab_size = st_size;
            ctx.strtab      = (const char *)st_ptr; /* les 4 premiers bytes = taille */
        }
    }

    /* ?? 3. Allouer memoire pour les sections ??????????????? */
    ctx.sec_mem = (BYTE **)calloc(ctx.hdr->NumberOfSections, sizeof(BYTE *));
    if (!ctx.sec_mem) {
        result.status    = -1;
        result.error_msg = _strdup("[BOF] calloc sec_mem echoue");
        return result;
    }

    /* Table de trampolines : MAX_TRAMPOLINES ? TRAMPOLINE_SIZE bytes
     * PAGE_EXECUTE_READWRITE car les stubs (jmp [rip+0]) sont du CODE. */
    ctx.trampolines = (BYTE *)VirtualAlloc(
        NULL,
        (size_t)MAX_TRAMPOLINES * TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!ctx.trampolines) {
        free(ctx.sec_mem);
        result.status    = -1;
        result.error_msg = _strdup("[BOF] VirtualAlloc trampolines echoue");
        return result;
    }

    for (WORD s = 0; s < ctx.hdr->NumberOfSections; s++) {
        CoffSectionHdr *sec = &ctx.sections[s];

        /* Ignorer les sections de debug / metadonnees            */
        char sname[9] = {0};
        memcpy(sname, sec->Name, 8);
        if (strncmp(sname, ".debug", 6) == 0 ||
            strncmp(sname, ".pdata", 6) == 0 ||
            strncmp(sname, ".xdata", 6) == 0 ||
            strncmp(sname, ".drect", 6) == 0)
            continue;

        DWORD sz = sec->SizeOfRawData ? sec->SizeOfRawData : sec->VirtualSize;
        if (sz == 0) continue;

        /* RWX pendant le chargement ; permissions finales apres  */
        ctx.sec_mem[s] = (BYTE *)VirtualAlloc(
            NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        );
        if (!ctx.sec_mem[s]) {
            printf("[BOF] VirtualAlloc echoue section %s (%lu bytes)\n", sname, (unsigned long)sz);
            goto cleanup;
        }

        if (sec->PointerToRawData && sec->SizeOfRawData)
            memcpy(ctx.sec_mem[s], bof_bytes + sec->PointerToRawData,
                   sec->SizeOfRawData);
        else
            ZeroMemory(ctx.sec_mem[s], sz); /* .bss : deja a 0    */

        printf("[BOF] Section %-8s @ %p (%lu bytes chars=0x%08lx)\n",
               sname, (void *)ctx.sec_mem[s], (unsigned long)sz,
               (unsigned long)sec->Characteristics);
    }

    /* ?? 4. Appliquer les relocalisations ???????????????????? */
    for (WORD s = 0; s < ctx.hdr->NumberOfSections; s++) {
        if (!ctx.sec_mem[s]) continue;
        if (!apply_relocations(&ctx, s)) {
            char err[64];
            snprintf(err, sizeof(err),
                     "[BOF] Relocalisations echouees section %d", s);
            result.status    = -1;
            result.error_msg = _strdup(err);
            goto cleanup;
        }
    }

    /* ?? 5. Permissions memoire ?????????????????????????????? *
     * On conserve PAGE_EXECUTE_READWRITE pour toutes les      *
     * sections. Les fichiers COFF generes par GCC/MinGW       *
     * marquent .rdata sans le bit WRITE (0x40400040), mais    *
     * le runtime BOF y accede en ecriture (pointeurs fmt,     *
     * descripteurs de fonctions). Toute tentative de          *
     * VirtualProtect > PAGE_READONLY provoque un crash.       *
     * RWX est acceptable dans un contexte C2 de recherche.   */

    /* ?? 6. Localiser le point d'entree 'go' ???????????????? */
    typedef void (*GoFn)(char *, int);
    GoFn go_fn = NULL;
    char nbuf[16];

    if (ctx.symtab_raw) {
        DWORD i = 0;
        while (i < ctx.hdr->NumberOfSymbols) {
            CoffSym sym;
            sym_get(&ctx, i, &sym);
            const char *sn = sym_name(&ctx, &sym, nbuf, sizeof(nbuf));

            if ((strcmp(sn, "go") == 0 || strcmp(sn, "_go") == 0)
                && sym.SectionNumber > 0) {
                int ts = sym.SectionNumber - 1;
                if (ts < (int)ctx.hdr->NumberOfSections && ctx.sec_mem[ts])
                    go_fn = (GoFn)(ctx.sec_mem[ts] + sym.Value);
            }
            i += 1 + sym.NumberOfAuxSymbols; /* sauter les auxiliaires */
        }
    }

    if (!go_fn) {
        result.status    = -1;
        result.error_msg = _strdup("[BOF] Symbole 'go' introuvable dans le COFF");
        goto cleanup;
    }

    /* ?? 7. Appeler go(args, args_len) ??????????????????????? */
    printf("[BOF] Appel go() @ %p\n", (void *)go_fn);
    fflush(stdout);

    beacon_reset_output();

    /* MinGW ne supporte pas __try/__except (MSVC SEH).
     * L'appel est direct : un BOF qui crashe entraine le crash
     * du processus agent - comportement acceptable en contexte R&D. */
    go_fn((char *)args, (int)args_len);

    /* ?? 8. Recuperer la sortie Beacon ??????????????????????? */
    {
        beacon_output_t *out = beacon_get_output();
        if (out && out->buffer && out->length > 0) {
            result.data = (unsigned char *)malloc(out->length + 1);
            if (result.data) {
                memcpy(result.data, out->buffer, out->length);
                result.data[out->length] = '\0';
                result.data_len = out->length;
                result.status   = 0;
            }
        } else {
            const char *msg = "[BOF] Execution reussie (aucune sortie)";
            result.data     = (unsigned char *)_strdup(msg);
            result.data_len = strlen(msg);
            result.status   = 0;
        }
    }

    printf("[BOF] Sortie : %zu bytes\n", result.data_len);
    fflush(stdout);

cleanup:
    /* ?? 9. Liberer toute la memoire allouee ???????????????? */
    if (ctx.sec_mem) {
        for (WORD s = 0; s < ctx.hdr->NumberOfSections; s++)
            if (ctx.sec_mem[s])
                VirtualFree(ctx.sec_mem[s], 0, MEM_RELEASE);
        free(ctx.sec_mem);
    }
    if (ctx.trampolines)
        VirtualFree(ctx.trampolines, 0, MEM_RELEASE);

    return result;
}

/* ============================================================
 *  STUB LINUX
 * ============================================================ */
#else

module_result_t coff_loader_execute(
    const unsigned char *bof_bytes, size_t bof_size,
    const unsigned char *args,      size_t args_len)
{
    (void)bof_bytes; (void)bof_size; (void)args; (void)args_len;
    module_result_t r = {0};
    r.status    = -1;
    r.error_msg = strdup("[BOF] Technique non supportee sur Linux");
    return r;
}

#endif /* PLATFORM_WINDOWS */
