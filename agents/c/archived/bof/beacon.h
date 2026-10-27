/*
 * ============================================================
 *  beacon.h — API Beacon pour modules BOF et DLL
 *
 *  BOF  mode (-DBOF_MODE)  : compile en COFF .o
 *                            types Windows définis ici (pas windows.h)
 *                            LIB$Func résolu par coff_loader au run-time
 *
 *  RDLL mode (-DRDLL_MODE) : compile en DLL .dll
 *                            types et API via <windows.h>
 *                            LIB$Func remappé directement vers la fonction
 *
 *  Auteur  : El Mazdougui Anass
 *  Date    : Avril 2026
 *  Projet  : Framework C2 Modulaire — PFE INPT 2026
 * ============================================================ */
#ifndef BEACON_H
#define BEACON_H

/* ==============================================================
 *  MODE RDLL — compilation DLL native
 *  Inclure windows.h en premier ; remapper LIB$Func → Func
 * ============================================================== */
#ifdef RDLL_MODE

#include <windows.h>

/* ── Macros d'import : en mode DLL c'est simplement dllimport ── */
#ifndef DECLSPEC_IMPORT
#  define DECLSPEC_IMPORT  __declspec(dllimport)
#endif

/* ── Remappage KERNEL32$Func → Func ────────────────────────── */
#define KERNEL32$CloseHandle               CloseHandle
#define KERNEL32$CreateDirectoryA          CreateDirectoryA
#define KERNEL32$CreateFileA               CreateFileA
#define KERNEL32$CreatePipe                CreatePipe
#define KERNEL32$CreateToolhelp32Snapshot  CreateToolhelp32Snapshot
#define KERNEL32$GetFileSize               GetFileSize
#define KERNEL32$OpenProcess               OpenProcess
#define KERNEL32$Process32First            Process32First
#define KERNEL32$Process32Next             Process32Next
#define KERNEL32$TerminateProcess          TerminateProcess
#define KERNEL32$CreateProcessA        CreateProcessA
#define KERNEL32$DeleteFileA           DeleteFileA
#define KERNEL32$FindClose             FindClose
#define KERNEL32$FindFirstFileA        FindFirstFileA
#define KERNEL32$FindNextFileA         FindNextFileA
#define KERNEL32$GetComputerNameA      GetComputerNameA
#define KERNEL32$GetCurrentDirectoryA  GetCurrentDirectoryA
#define KERNEL32$GetCurrentProcess     GetCurrentProcess
#define KERNEL32$GetCurrentProcessId   GetCurrentProcessId
#define KERNEL32$GetExitCodeProcess    GetExitCodeProcess
#define KERNEL32$GetFileAttributesA    GetFileAttributesA
#define KERNEL32$GetLastError          GetLastError
#define KERNEL32$GetNativeSystemInfo   GetNativeSystemInfo
#define KERNEL32$GetProcessHeap        GetProcessHeap
#define KERNEL32$GetUserNameA          GetUserNameA
#define KERNEL32$GetVersionExA         GetVersionExA
#define KERNEL32$HeapAlloc             HeapAlloc
#define KERNEL32$HeapFree              HeapFree
#define KERNEL32$IsWow64Process        IsWow64Process
#define KERNEL32$ReadFile              ReadFile
#define KERNEL32$SetHandleInformation  SetHandleInformation
#define KERNEL32$WriteFile             WriteFile
#define KERNEL32$WaitForSingleObject   WaitForSingleObject

/* ── Remappage GDI32$Func → Func ────────────────────────────── */
#define GDI32$BitBlt                   BitBlt
#define GDI32$CreateCompatibleBitmap   CreateCompatibleBitmap
#define GDI32$CreateCompatibleDC       CreateCompatibleDC
#define GDI32$DeleteDC                 DeleteDC
#define GDI32$DeleteObject             DeleteObject
#define GDI32$GetDIBits                GetDIBits
#define GDI32$SelectObject             SelectObject

/* ── Remappage USER32$Func → Func ───────────────────────────── */
#define USER32$GetDC                   GetDC
#define USER32$GetSystemMetrics        GetSystemMetrics
#define USER32$ReleaseDC               ReleaseDC

/* ── Aliases de types (les modules utilisent ces noms locaux) ── */
typedef SYSTEM_INFO      _SYSTEM_INFO;
typedef OSVERSIONINFOA   _OSVERSIONINFOA;
typedef WIN32_FIND_DATAA _WIN32_FIND_DATA;

/* ── Export de go() dans la DLL ────────────────────────────── */
#define BOF_DLL_EXPORT   __declspec(dllexport)

#else  /* ──── BOF MODE ───────────────────────────────────────── */

/* ── Types Windows minimaux (sans #include <windows.h>) ──────
 * Couvre tous les types utilisés dans les modules BOF fournis.  */

#ifdef _WIN64
  typedef unsigned long long  ULONG_PTR;
  typedef          long long  LONG_PTR;
#else
  typedef unsigned long       ULONG_PTR;
  typedef          long       LONG_PTR;
#endif

typedef unsigned long       DWORD;
typedef unsigned short      WORD;
typedef unsigned char       BYTE;
typedef int                 BOOL;
typedef int                 INT;
typedef unsigned int        UINT;
typedef long                LONG;
typedef char                CHAR;
typedef ULONG_PTR           SIZE_T;
typedef ULONG_PTR           DWORD_PTR;

#ifndef _SIZE_T_DEFINED
  typedef ULONG_PTR         size_t;
  #define _SIZE_T_DEFINED
#endif

typedef void *              HANDLE;
typedef void *              HWND;
typedef void *              HDC;
typedef void *              HBITMAP;
typedef void *              HGDIOBJ;
typedef void *              HINSTANCE;

typedef char *              LPSTR;
typedef const char *        LPCSTR;
typedef unsigned char *     LPBYTE;
typedef unsigned long *     LPDWORD;
typedef int *               PBOOL;
typedef HANDLE *            PHANDLE;
typedef void *              LPVOID;
typedef const void *        LPCVOID;
typedef void *              LPOVERLAPPED;
typedef void *              LPSECURITY_ATTRIBUTES;
typedef void *              LPSTARTUPINFOA;
typedef void *              LPPROCESS_INFORMATION;
typedef void *              LPWIN32_FIND_DATAA;
typedef void *              LPOSVERSIONINFOA;
typedef void *              LPSYSTEM_INFO;
typedef void *              LPBITMAPINFO;

/* Calling conventions (can be empty on x64, kept for compatibility) */
#ifndef WINAPI
#  define WINAPI   __stdcall
#endif
#ifndef WINBASEAPI
#  define WINBASEAPI  __declspec(dllimport)
#endif

#ifdef _WIN32
#  define DECLSPEC_IMPORT  __declspec(dllimport)
#else
#  define DECLSPEC_IMPORT  extern
#endif

#define BOF_DLL_EXPORT  /* nothing in BOF mode */

#ifndef NULL
#  define NULL ((void*)0)
#endif
#ifndef TRUE
#  define TRUE  1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

#endif /* RDLL_MODE */


/* ==============================================================
 *  SECTION COMMUNE — constantes, structures, API Beacon
 * ============================================================== */

/* ── Types de sortie Beacon ─────────────────────────────────── */
#define CALLBACK_OUTPUT       0x00
#define CALLBACK_OUTPUT_OEM   0x1e
#define CALLBACK_OUTPUT_UTF8  0x20
#define CALLBACK_ERROR        0x0d

/* ── Structures pour les arguments packés ───────────────────── */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

/* ── API Beacon (déclarée extern ; résolue par le loader) ───── */
void  BeaconOutput(int type, const char *data, int len);
void  BeaconPrintf(int type, const char *fmt, ...);

void  BeaconDataParse(datap *parser, char *buffer, int size);
char *BeaconDataExtract(datap *parser, int *size);
int   BeaconDataInt(datap *parser);
short BeaconDataShort(datap *parser);
int   BeaconDataLength(datap *parser);

void  BeaconFormatAlloc(formatp *format, int maxsz);
void  BeaconFormatReset(formatp *format);
void  BeaconFormatFree(formatp *format);
void  BeaconFormatAppend(formatp *format, const char *data, int len);
void  BeaconFormatPrintf(formatp *format, const char *fmt, ...);
char *BeaconFormatToString(formatp *format, int *size);
void  BeaconFormatInt(formatp *format, int value);

int   BeaconIsAdmin(void);
int   BeaconIsInSession(void);

#endif /* BEACON_H */
