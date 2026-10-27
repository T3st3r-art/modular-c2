#!/usr/bin/env python3
"""
srdi.py — Convertisseur DLL → format sRDI (.bin)
=================================================

sRDI : Shellcode Reflective DLL Injection
MITRE ATT&CK : T1620 (Reflective Code Loading)

Ce script convertit une DLL réflective (.x64.dll) en un fichier .bin
au format sRDI reconnu par le shellcode_loader de l'agent.

Format de sortie (.bin) :
    Offset   Taille   Contenu
    ──────   ──────   ──────────────────────────────────────────
    0        4        Magic : "SRDI" (0x53 0x52 0x44 0x49)
    4        1        Version : 0x00
    5        1        Architecture : 0x40=x64 | 0x20=x86
    6        2        Réservé : 0x00 0x00
    8        N        Bytes de la DLL (PE complet, inchangé)

Côté agent (shellcode_execute) :
    1. Détecte le magic "SRDI"
    2. Lit l'arch depuis l'octet [5]
    3. Strip les 8 bytes de header
    4. Passe les N bytes de DLL à rdll_loader_execute()
    → le chargeur PE reflectif fait le reste (sections, relocations, IAT, go())

Différence avec un vrai sRDI :
    Un vrai sRDI contient un bootstrap position-independent (PIC)
    qui intègre le reflective loader et peut s'exécuter seul dans
    n'importe quel processus (sans l'agent). Notre implémentation
    requiert que rdll_loader soit présent dans le processus agent.
    Cette approche est suffisante pour l'exécution in-process (T1059)
    mais pas pour l'injection cross-process (T1055) avec des DLLs.

Usage :
    python3 srdi.py sysinfo.x64.dll
        → produit sysinfo.x64.bin dans le même répertoire

    python3 srdi.py sysinfo.x64.dll -o output/sysinfo.x64.bin

    python3 srdi.py --all
        → convertit tous les .x64.dll dans server/modules/

Auteur  : El Mazdougui Anass
Date    : Avril 2026
Projet  : Framework C2 Modulaire — PFE INPT 2026
"""

import argparse
import os
import struct
import sys

# Console Windows (cp1252) : autoriser les caractères UTF-8 (→)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ──────────────────────────────────────────────────────────────
#  Constantes du format sRDI
# ──────────────────────────────────────────────────────────────
SRDI_MAGIC   = b'SRDI'
SRDI_VERSION = 0x00
SRDI_ARCH_X64 = 0x40
SRDI_ARCH_X86 = 0x20
SRDI_HDR_SIZE = 8

# Répertoire des modules (relatif au script)
MODULES_DIR = os.path.join(os.path.dirname(__file__), "modules")


def detect_arch_from_pe(dll_bytes: bytes) -> int:
    """
    Lit le champ Machine de l'en-tête PE pour déterminer l'architecture.
    Retourne SRDI_ARCH_X64 ou SRDI_ARCH_X86.
    """
    if len(dll_bytes) < 64:
        return SRDI_ARCH_X64  # défaut x64

    # e_lfanew à l'offset 0x3C
    e_lfanew = struct.unpack_from('<I', dll_bytes, 0x3C)[0]
    if e_lfanew + 6 > len(dll_bytes):
        return SRDI_ARCH_X64

    # Machine (2 bytes) à NT_HEADER + 4
    machine = struct.unpack_from('<H', dll_bytes, e_lfanew + 4)[0]

    if machine == 0x8664:   # IMAGE_FILE_MACHINE_AMD64
        return SRDI_ARCH_X64
    elif machine == 0x014C:  # IMAGE_FILE_MACHINE_I386
        return SRDI_ARCH_X86
    else:
        return SRDI_ARCH_X64  # défaut


def build_srdi_header(arch: int) -> bytes:
    """Construit le header sRDI 8 bytes."""
    return struct.pack('<4sBBBB',
                       SRDI_MAGIC,
                       SRDI_VERSION,
                       arch,
                       0x00, 0x00)


def convert_dll_to_srdi(dll_path: str, bin_path: str = None) -> str:
    """
    Convertit un fichier DLL en format sRDI (.bin).

    Args:
        dll_path : chemin vers le .dll source
        bin_path : chemin de sortie (défaut : même répertoire, extension .bin)

    Returns:
        Chemin du fichier .bin créé.

    Raises:
        FileNotFoundError : si dll_path n'existe pas
        ValueError        : si le fichier n'est pas un PE valide
    """
    if not os.path.isfile(dll_path):
        raise FileNotFoundError(f"Fichier introuvable : {dll_path}")

    with open(dll_path, 'rb') as f:
        dll_bytes = f.read()

    # Validation PE minimal
    if len(dll_bytes) < 64:
        raise ValueError(f"Fichier trop petit pour être un PE : {len(dll_bytes)} bytes")

    if dll_bytes[:2] != b'MZ':
        raise ValueError(f"Magic MZ manquant — pas un fichier PE valide")

    # Vérifier que c'est une DLL (IMAGE_FILE_DLL = 0x2000)
    e_lfanew = struct.unpack_from('<I', dll_bytes, 0x3C)[0]
    if e_lfanew + 22 <= len(dll_bytes):
        characteristics = struct.unpack_from('<H', dll_bytes, e_lfanew + 22)[0]
        if not (characteristics & 0x2000):
            print(f"  [!] Avertissement : {os.path.basename(dll_path)} "
                  f"ne semble pas être une DLL (IMAGE_FILE_DLL absent)")

    # Détection architecture
    arch = detect_arch_from_pe(dll_bytes)
    arch_str = "x64" if arch == SRDI_ARCH_X64 else "x86"

    # Chemin de sortie
    if not bin_path:
        bin_path = dll_path.rsplit('.dll', 1)[0] + '.bin'
        # Normaliser l'extension : sysinfo.x64.dll → sysinfo.x64.bin
        bin_path = dll_path.replace('.dll', '.bin')

    # Construction du .bin
    header    = build_srdi_header(arch)
    bin_bytes = header + dll_bytes

    os.makedirs(os.path.dirname(os.path.abspath(bin_path)), exist_ok=True)
    with open(bin_path, 'wb') as f:
        f.write(bin_bytes)

    print(f"  [sRDI] {os.path.basename(dll_path)} ({arch_str}) "
          f"→ {os.path.basename(bin_path)} "
          f"({len(dll_bytes)} + {SRDI_HDR_SIZE} = {len(bin_bytes)} bytes)")

    return bin_path


def convert_all_modules(modules_dir: str = MODULES_DIR, arch: str = "x64") -> int:
    """
    Parcourt tous les sous-répertoires de modules_dir et convertit
    chaque .x64.dll en .x64.bin.

    Returns:
        Nombre de fichiers convertis.
    """
    if not os.path.isdir(modules_dir):
        print(f"[!] Répertoire modules introuvable : {modules_dir}")
        return 0

    converted = 0
    dll_ext = f".{arch}.dll"

    for module_name in sorted(os.listdir(modules_dir)):
        module_dir = os.path.join(modules_dir, module_name)
        if not os.path.isdir(module_dir):
            continue

        dll_file = os.path.join(module_dir, f"{module_name}{dll_ext}")
        if not os.path.isfile(dll_file):
            continue

        try:
            convert_dll_to_srdi(dll_file)
            converted += 1
        except (ValueError, IOError) as e:
            print(f"  [!] Erreur sur {module_name}: {e}")

    return converted


def verify_srdi_file(bin_path: str) -> bool:
    """
    Vérifie qu'un fichier .bin est bien au format sRDI.

    Returns:
        True si valide, False sinon.
    """
    if not os.path.isfile(bin_path):
        print(f"[!] Fichier introuvable : {bin_path}")
        return False

    with open(bin_path, 'rb') as f:
        header = f.read(SRDI_HDR_SIZE)

    if len(header) < SRDI_HDR_SIZE:
        print(f"[!] Fichier trop petit pour un header sRDI")
        return False

    if header[:4] != SRDI_MAGIC:
        print(f"[!] Magic sRDI manquant (obtenu : {header[:4].hex()})")
        return False

    version = header[4]
    arch    = header[5]
    arch_str = "x64" if arch == SRDI_ARCH_X64 else \
               "x86" if arch == SRDI_ARCH_X86 else f"0x{arch:02X}"

    file_size = os.path.getsize(bin_path)
    dll_size  = file_size - SRDI_HDR_SIZE

    print(f"[sRDI] {os.path.basename(bin_path)}")
    print(f"  Magic   : SRDI ✓")
    print(f"  Version : {version}")
    print(f"  Arch    : {arch_str}")
    print(f"  DLL     : {dll_size} bytes")
    print(f"  Total   : {file_size} bytes")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Convertisseur DLL → sRDI (.bin) pour C2 Framework PFE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python3 srdi.py modules/sysinfo/sysinfo.x64.dll
  python3 srdi.py modules/sysinfo/sysinfo.x64.dll -o /tmp/sysinfo.x64.bin
  python3 srdi.py --all
  python3 srdi.py --all --arch x64
  python3 srdi.py --verify modules/sysinfo/sysinfo.x64.bin
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        'dll_file',
        nargs='?',
        help="Fichier DLL à convertir"
    )
    group.add_argument(
        '--all',
        action='store_true',
        help=f"Convertir tous les .dll dans {MODULES_DIR}/"
    )
    group.add_argument(
        '--verify',
        metavar='BIN_FILE',
        help="Vérifier un fichier .bin sRDI existant"
    )

    parser.add_argument(
        '-o', '--output',
        metavar='OUTPUT',
        help="Fichier de sortie .bin (mode fichier unique uniquement)"
    )
    parser.add_argument(
        '--arch',
        choices=['x64', 'x86'],
        default='x64',
        help="Architecture cible pour --all (défaut: x64)"
    )
    parser.add_argument(
        '--modules-dir',
        default=MODULES_DIR,
        metavar='DIR',
        help=f"Répertoire des modules (défaut: {MODULES_DIR})"
    )

    args = parser.parse_args()

    if args.verify:
        ok = verify_srdi_file(args.verify)
        sys.exit(0 if ok else 1)

    if args.all:
        print(f"[sRDI] Conversion de tous les modules ({args.arch})...")
        n = convert_all_modules(args.modules_dir, args.arch)
        print(f"[sRDI] {n} module(s) converti(s) → prêts pour -t shellcode")
        sys.exit(0)

    if args.dll_file:
        try:
            out = convert_dll_to_srdi(args.dll_file, args.output)
            print(f"[sRDI] Succès : {out}")
            sys.exit(0)
        except (FileNotFoundError, ValueError) as e:
            print(f"[ERREUR] {e}")
            sys.exit(1)


if __name__ == '__main__':
    main()
