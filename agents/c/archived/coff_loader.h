/*
 * ============================================================
 *  coff_loader.h — COFF/BOF Object File Loader (Technique 1)
 *
 *  Rôle : Charge et exécute dynamiquement un fichier objet COFF
 *         (.o compilé MinGW/MSVC) directement en mémoire.
 *
 *  Pipeline d'exécution :
 *    1. Parsing de l'en-tête COFF et des sections
 *    2. Allocation mémoire RWX pour chaque section
 *    3. Résolution des symboles externes (LoadLibrary + GetProcAddress)
 *    4. Application des relocations (AMD64 uniquement)
 *    5. Recherche et appel de la fonction "go(args, args_len)"
 *    6. Récupération de la sortie via le buffer Beacon
 *    7. Libération de toute la mémoire allouée
 *
 *  Références :
 *    TrustedSec/COFFLoader  (github.com/trustedsec/COFFLoader)
 *    Microsoft PE/COFF Specification v8.3
 *
 *  Portabilité :
 *    Implémentation complète : Windows x64/x86
 *    Stub d'erreur : Linux (le loader ELF sera Technique 4)
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================
 */
#ifndef COFF_LOADER_H
#define COFF_LOADER_H

#include <stdint.h>
#include "platform.h"
#include "execution_engine.h"

/* ============================================================
 *  STRUCTURES COFF (pack 1 octet pour lecture directe)
 * ============================================================ */
#pragma pack(push, 1)

/** En-tête principal du fichier COFF (20 bytes). */
typedef struct {
    uint16_t Machine;              /* 0x8664 = AMD64, 0x014C = x86 */
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable; /* Offset absolu dans le fichier */
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader; /* 0 pour les .o                 */
    uint16_t Characteristics;
} coff_hdr_t;                      /* 20 bytes total */

/** Entrée de la table des sections (40 bytes). */
typedef struct {
    char     Name[8];              /* Nom, null-padded si < 8 chars */
    uint32_t VirtualSize;          /* Taille en mémoire             */
    uint32_t VirtualAddress;       /* 0 dans les .o (relocatable)   */
    uint32_t SizeOfRawData;        /* Taille sur disque             */
    uint32_t PointerToRawData;     /* Offset dans le fichier        */
    uint32_t PointerToRelocations; /* Offset table de relocations   */
    uint32_t PointerToLinenumbers; /* Ignoré                        */
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;  /* Ignoré                        */
    uint32_t Characteristics;      /* Flags : code, data, bss...    */
} coff_sec_t;                      /* 40 bytes total */

/** Entrée de relocation (10 bytes). */
typedef struct {
    uint32_t VirtualAddress;    /* Offset du patch dans la section */
    uint32_t SymbolTableIndex;  /* Index dans la table des symboles */
    uint16_t Type;              /* Type de relocation AMD64        */
} coff_reloc_t;                 /* 10 bytes total */

/** Entrée de la table des symboles (18 bytes). */
typedef struct {
    union {
        char     ShortName[8]; /* Nom inline si 4 premiers bytes != 0 */
        struct {
            uint32_t Zeros;    /* 0 si nom dans la string table        */
            uint32_t Offset;   /* Offset dans la string table          */
        } Long;
    } Name;
    uint32_t Value;            /* Valeur / offset selon le type        */
    int16_t  SectionNumber;    /* 1-based, 0 = extern, -1 = abs        */
    uint16_t Type;
    uint8_t  StorageClass;     /* 2 = EXTERNAL, 3 = STATIC, etc.       */
    uint8_t  NumberOfAuxSymbols;
} coff_sym_t;                  /* 18 bytes total */

#pragma pack(pop)

/* ============================================================
 *  CONSTANTES DE MACHINES COFF
 * ============================================================ */
#define COFF_MACHINE_AMD64  0x8664   /* x86-64 */
#define COFF_MACHINE_I386   0x014C   /* x86-32 */

/* ============================================================
 *  TYPES DE RELOCATIONS AMD64
 * ============================================================ */
#define IMAGE_REL_AMD64_ADDR64    0x0001  /* VA 64 bits absolue           */
#define IMAGE_REL_AMD64_ADDR32    0x0002  /* VA 32 bits absolue           */
#define IMAGE_REL_AMD64_ADDR32NB  0x0003  /* RVA 32 bits (image-relative) */
#define IMAGE_REL_AMD64_REL32     0x0004  /* Relatif PC 32 bits           */
#define IMAGE_REL_AMD64_REL32_1   0x0005  /* REL32 + 1 byte offset        */
#define IMAGE_REL_AMD64_REL32_2   0x0006
#define IMAGE_REL_AMD64_REL32_3   0x0007
#define IMAGE_REL_AMD64_REL32_4   0x0008
#define IMAGE_REL_AMD64_REL32_5   0x0009

/* ============================================================
 *  INTERFACE PUBLIQUE
 * ============================================================ */

/**
 * Charge et exécute un COFF/BOF en mémoire.
 *
 * @param coff_data  : bytes bruts du fichier .o
 * @param coff_size  : taille en bytes
 * @param args       : arguments packés pour "go()" (peut être NULL)
 * @param args_len   : taille des arguments
 *
 * @return module_result_t contenant la sortie du BOF.
 *         Toujours appeler free_module_result() après usage.
 */
module_result_t coff_loader_execute(
    const unsigned char *coff_data,
    size_t               coff_size,
    const unsigned char *args,
    size_t               args_len
);

#endif /* COFF_LOADER_H */
