# Modular C2 Framework — Red Team Project

> **⚠️ Avertissement** : Ce projet a été développé dans un cadre strictement académique (PFE INPT 2026) à des fins de recherche et de tests d'intrusion supervisés. Toutes les capacités offensives sont conçues pour s'exécuter exclusivement en mémoire (*in-memory*) et sont découplées du binaire de l'agent.

---

## Table des Matières

1. [Architecture du Projet](#1-architecture-du-projet)
2. [Fonctionnalités Avancées](#2-fonctionnalités-avancées)
3. [Prérequis Environnementaux](#3-prérequis-environnementaux)
4. [Installation et Configuration](#4-installation-et-configuration)
5. [Guide d'Utilisation](#5-guide-dutilisation)
6. [Vérification Rapide](#6-vérification-rapide)
7. [Dépannage (Troubleshooting)](#7-dépannage-troubleshooting)
8. [Structure des Répertoires](#8-structure-des-répertoires)

---

## 1. Architecture du Projet

Le framework est composé de trois composants entièrement découplés.

### 🖥️ Team Server (`server/`)

Développé en **Python** avec **FastAPI** et **SQLite** (`aiosqlite`). Hub central responsable de :

- La gestion de la file d'attente des tâches (Task Queue).
- La distribution des modules in-memory aux agents.
- La gestion du tunneling SOCKS5 inversé.
- L'obfuscation des payloads en transit (XOR).

### 🤖 Windows Agent (`agents/c/`)

Écrit en **C natif**, binaire compilé d'environ ~25 KB. Ne contient **aucun code offensif** en dur.

**Workflow :** Télécharge les modules (RDLL/BOF) → les exécute en mémoire (`VirtualAlloc` → copie → exécution) → libère la mémoire (`VirtualFree`).

Utilise un **Dispatch Dynamique** (Pattern Strategy en C) : le cœur de l'agent (`core.c`) ne connaît pas les modules à la compilation, il les charge via une table de pointeurs de fonctions.

### 🎮 Console Opérateur (`operator/`)

Développée en **Python** avec **prompt_toolkit**. CLI interactive avec auto-complétion par tabulation et historique persistant. Permet de gérer les agents, d'assigner des tâches et de visualiser les résultats en temps réel.

---

## 2. Fonctionnalités Avancées

### 🛡️ Obfuscation des Payloads `(MITRE ATT&CK T1027)`

Tous les modules transférés entre le serveur et l'agent sont **obfusqués via XOR**, en utilisant l'`agent_id` unique de la cible comme clé de chiffrement. Cela empêche l'inspection en clair du trafic réseau (ex : via Wireshark).

### 💉 Injection Furtive Early Bird APC `(MITRE ATT&CK T1055.004)`

Le framework inclut une technique d'injection avancée (`apcinject_stealth`) qui contourne les heuristiques de base des EDR :

1. **Transition Mémoire RW → RX** : La mémoire est allouée en `PAGE_READWRITE`, le shellcode y est écrit, puis la protection est changée en `PAGE_EXECUTE_READ` juste avant l'exécution. La région n'est **jamais** `RWX`.
2. **Résolution Dynamique des API** : Les appels à `kernel32.dll` sont résolus via `GetProcAddress` pour contourner les hooks user-mode installés par les EDR.

### 🕵️ Suite de Reconnaissance Active Directory (In-Memory)

Le framework intègre **9 modules spécialisés** en C natif (via `winldap.h`), évitant le chargement du runtime .NET (`clr.dll`) et les déclencheurs AMSI/ETW associés.

| Module | Description | MITRE ATT&CK |
|---|---|---|
| `adcomputers` | Énumération des machines du domaine et OS | T1018 |
| `adusers` | Énumération des utilisateurs et attributs | T1087.002 |
| `adgroups` | Énumération des groupes et de leurs membres (gère les Primary Groups) | T1069.002 |
| `adspn` | Identification des comptes avec SPN (Cibles Kerberoasting) | T1558.003 |
| `adpreauth` | Identification des comptes sans pré-authentification (AS-REP Roasting) | T1558.002 |
| `adgpo` | Énumération des Group Policy Objects et liaisons OU | T1484.001 |
| `adou` | Cartographie des Unités d'Organisation et de leurs enfants directs | T1069.002 |
| `adpwdpolicy` | Analyse de la politique de mot de passe du domaine (verrouillage, complexité) | T1218 |
| `admaq` | Vérification du Machine Account Quota (Prérequis RBCD) | T1078 |

---

## 3. Prérequis Environnementaux

### Serveur & Console Opérateur

| Requis | Version |
|---|---|
| Python | 3.10 ou supérieur |
| pip | Dernière version |

### Agent C (Compilation — Windows)

L'agent nécessite **MSYS2 MinGW64** pour être compilé sous Windows.

1. Téléchargez et installez [MSYS2](https://www.msys2.org/).
2. Ouvrez le terminal **MSYS2 MinGW 64-bit** et installez la toolchain :

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-i686-gcc make
```

---

## 4. Installation et Configuration

Depuis la racine du projet, créez et activez un environnement virtuel Python, puis installez les dépendances :

```bash
# Créer l'environnement virtuel
python -m venv venv

# Activation (Windows)
venv\Scripts\activate

# Activation (Linux / macOS)
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

---

## 5. Guide d'Utilisation

### Étape A — Démarrer le Team Server

Ouvrez un terminal, activez l'environnement virtuel et lancez :

```bash
python server/main.py
```

> Le serveur commencera à écouter les connexions des agents et de l'opérateur.

### Étape B — Démarrer la Console Opérateur

Ouvrez un nouveau terminal, activez l'environnement virtuel et lancez :

```bash
python -m operator.main
```

Utilisez la touche `Tab` pour explorer les commandes disponibles. Connectez-vous avec `login <votre_nom>`.

### Étape C — Compiler l'Agent C

Ouvrez le terminal **MSYS2 MinGW 64-bit** :

```bash
cd agents/c
make windows
```

> Cela génère `agent.exe` dans le dossier `agents/c/`.

### Étape D — Compiler les Modules In-Memory

Toujours dans le terminal MSYS2 MinGW 64-bit (`agents/c/`) :

```bash
make dll-x64
```

> Les modules compilés (`.x64.dll`) seront placés dans `server/modules/`, le répertoire que le Team Server sert aux agents.

---

## 6. Vérification Rapide

### ✅ Connectivité de Base

1. Assurez-vous que le Team Server et la Console Opérateur sont en cours d'exécution.
2. Exécutez `agent.exe` sur une machine virtuelle de test.
3. L'agent devrait apparaître comme actif dans la console (`list`).
4. Lancez une commande de test :

```bash
use <agent_id>
module sysinfo -t rdll
```

### ✅ Tunnel SOCKS5

Depuis la machine de l'opérateur (Kali/Parrot) :

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```

> Une réponse HTTP 200 confirme que le tunnel est opérationnel.

### ✅ Obfuscation XOR

Capturez le trafic entre l'agent et le serveur avec Wireshark. Les payloads des modules doivent apparaître comme des données binaires obfusquées (XOR) et **non** comme des fichiers PE en clair.

### ✅ Reconnaissance AD

Testez la suite AD sur une machine jointe au domaine :

```bash
module adcomputers -t rdll
module adspn -t rdll
```

---

## 7. Dépannage (Troubleshooting)

| Problème | Cause Probable | Solution |
|---|---|---|
| `make` échoue dans MSYS2 | Mauvais terminal utilisé | Utilisez **MSYS2 MinGW 64-bit** (pas le terminal MSYS de base). Vérifiez avec `which gcc`. |
| L'agent ne se connecte pas | IP/Port incorrects | Vérifiez `agents/c/config.h`. Assurez-vous que le serveur est accessible depuis la VM (pare-feu, réseau). |
| Erreur `422 Unprocessable Content` | Désynchronisation Agent/Serveur | Si vous avez récemment mergé la branche d'obfuscation, recompilez l'agent (`make windows`) pour qu'il envoie correctement l'`agent_id` requis pour le déchiffrement XOR. |
| `ModuleNotFoundError` au démarrage | Dépendances manquantes | Ré-exécutez `pip install -r requirements.txt` dans l'environnement virtuel activé. |
| Le module AD renvoie une erreur | Machine hors domaine | Les modules `ad*` nécessitent que l'agent s'exécute sur une machine jointe à un domaine Active Directory. |

---

## 8. Structure des Répertoires

```
modular-c2-framework/
├── agents/
│   └── c/                   # Code source de l'agent C natif & Makefile
│       ├── config.h         # Configuration (IP, Port)
│       ├── core.c           # Moteur de polling et dispatch dynamique
│       ├── shell.c          # Shell persistant avec mécanisme Sentinel
│       └── modules/dll/     # Code source des modules RDLL (sysinfo, ad*.c, etc.)
├── operator/
│   ├── main.py              # Point d'entrée de la console CLI
│   └── commands.py          # Gestionnaire des commandes opérateur
├── server/
│   ├── main.py              # Point d'entrée du serveur FastAPI
│   ├── database.py          # Gestion SQLite
│   ├── routes/              # Endpoints API (agent, operator, modules, tunnel)
│   └── modules/             # Répertoire contenant les .dll compilés servis aux agents
├── .gitignore
├── requirements.txt
└── README.md
```