#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

static LONG WINAPI GetCurrentPackageId(uint32_t bufferLength, BYTE buffer)
{
    DebugLog("");
    //return APPMODEL_ERROR_NO_PACKAGE value
    return 15700L;
}

static HANDLE WINAPI LoadLibraryExW(PVOID lpFileName, HANDLE hFile, DWORD dwFlags) {
    char *name = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %p, %#x", lpFileName, name, hFile, dwFlags);

    free(name);

    return (HANDLE) 'LOAD';
}

static HANDLE WINAPI LoadLibraryW(PVOID lpFileName) {
    DebugLog("%p", lpFileName);

    return (HANDLE) 'LOAD';
}

static PVOID WINAPI GetProcAddress(HANDLE hModule, PCHAR lpProcName) {
    ENTRY key = {lpProcName}, *item;

    assert(hModule == (HANDLE) NULL || hModule == (HANDLE) 'LOAD' || hModule == (HANDLE) 'MPEN' ||
           hModule == (HANDLE) 'VERS' || hModule == (HANDLE) 'KERN');

    if (hsearch_r(key, FIND, &item, &crtexports)) {
        return item->data;
    }

    DebugLog("FIXME: %s unresolved", lpProcName);

    return NULL;
}

static HANDLE WINAPI GetModuleHandleW(PVOID lpModuleName) {
    char *name = CreateAnsiFromWide(lpModuleName);

    DebugLog("%p [%s]", lpModuleName, name);

    free(name);

    if (lpModuleName && memcmp(lpModuleName, L"mpengine.dll", sizeof(L"mpengine.dll")) == 0)
        return (HANDLE) 'MPEN';

    if (lpModuleName && memcmp(lpModuleName, L"bcrypt.dll", sizeof(L"bcrypt.dll")) == 0)
        return (HANDLE) 'LOAD';

    if (lpModuleName && memcmp(lpModuleName, L"KERNEL32.DLL", sizeof(L"KERNEL32.DLL")) == 0)
        return (HANDLE) 'KERN';

    if (lpModuleName && memcmp(lpModuleName, L"kernel32.dll", sizeof(L"kernel32.dll")) == 0)
        return (HANDLE) 'KERN';

    if (lpModuleName && memcmp(lpModuleName, L"version.dll", sizeof(L"version.dll")) == 0)
        return (HANDLE) 'VERS';
    return (HANDLE) NULL;
}

static DWORD WINAPI GetModuleFileNameA(HANDLE hModule, PCHAR lpFilename, DWORD nSize) {
    DebugLog("%p, %p, %u", hModule, lpFilename, nSize);

    strncpy(lpFilename, "C:\\dummy\\fakename.exe", nSize);

    return strlen(lpFilename);
}

static DWORD WINAPI GetModuleFileNameW(HANDLE hModule, PWCHAR lpFilename, DWORD nSize) {
    DebugLog("%p, %p, %u", hModule, lpFilename, nSize);

    if (nSize > strlen("C:\\dummy\\fakename.exe")) {
        memcpy(lpFilename, L"C:\\dummy\\fakename.exe", sizeof(L"C:\\dummy\\fakename.exe"));
    }

    return strlen("C:\\dummy\\fakename.exe");
}

static HANDLE WINAPI GetModuleHandleA(PCHAR lpModuleName) {
    DebugLog("%p [%s]", lpModuleName, lpModuleName);

    return (HANDLE) NULL;
}

static BOOL WINAPI GetModuleHandleExA(DWORD dwFlags,
                                      LPCSTR lpModuleName,
                                      HMODULE *phModule) {
    DebugLog("%p [%s]", lpModuleName, lpModuleName);

    if (lpModuleName && memcmp(lpModuleName, "mpengine.dll", sizeof("mpengine.dll")) == 0)
        *phModule = (HANDLE) 'MPEN';

    if (lpModuleName && memcmp(lpModuleName, "bcrypt.dll", sizeof("bcrypt.dll")) == 0)
        *phModule = (HANDLE) 'LOAD';

    if (lpModuleName && memcmp(lpModuleName, "KERNEL32.DLL", sizeof("KERNEL32.DLL")) == 0)
        *phModule = (HANDLE) 'KERN';

    if (lpModuleName && memcmp(lpModuleName, "kernel32.dll", sizeof("kernel32.dll")) == 0)
        *phModule = (HANDLE) 'KERN';

    if (lpModuleName && memcmp(lpModuleName, "version.dll", sizeof("version.dll")) == 0)
        *phModule = (HANDLE) 'VERS';

    if (lpModuleName && memcmp(lpModuleName, "ntdll.dll", sizeof("ntdll.dll")) == 0)
        *phModule = (HANDLE) 'NTDL';

    *phModule = (HANDLE) NULL;
    return true;
}

#ifdef __x86_64__
static BOOL WINAPI GetModuleHandleExW(DWORD dwFlags,
                                      LPCWSTR lpModuleName,
                                      HMODULE *phModule) {
    DebugLog("%p flags: %x", lpModuleName, dwFlags);
    DebugLog("This is probably not handled correctly...");
    if (dwFlags & 4){ // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
	DebugLog("GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS");
    	uintptr_t ptr_val=(uintptr_t)lpModuleName;
	DebugLog("%llx, %llx", ptr_val, ptr_val & 0x75a000000);
        if ((ptr_val & 0x75a000000) == 0x75a000000){
            *phModule = (HANDLE) 'MPEN';
            return true;
        }else{
	    DebugLog("Can't resolve address: %p", lpModuleName);
            *phModule = (HANDLE) 'LOAD';
            return true;
	    exit(1);
	}
    }else{
	char a_name[300];
	for (int i=0; lpModuleName[i*2]!=0 && i < 150; i++){
	  a_name[i]=(char*)lpModuleName[i*2];
	}
	return GetModuleHandleExA(dwFlags, a_name, phModule);
    }
    *phModule = (HANDLE) NULL;
    return true;
}

#else
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 0x00000004
#define ERROR_MOD_NOT_FOUND 126

extern void WINAPI SetLastError(DWORD dwErrCode);

static BOOL WINAPI GetModuleHandleExW(DWORD dwFlags, PVOID lpModuleName, HANDLE *phModule)
{
    DebugLog("%#x, %p, %p", dwFlags, lpModuleName, phModule);

    // The only module that code can live in is the one we loaded.
    if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
        *phModule = (HANDLE) 'MPEN';
        return TRUE;
    }

    if ((*phModule = GetModuleHandleW(lpModuleName)) == NULL) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return FALSE;
    }

    return TRUE;
}

#endif

static VOID WINAPI FreeLibrary(PVOID hLibModule) {
    DebugLog("FreeLibrary(%p)", hLibModule);
}

DECLARE_CRT_EXPORT("GetCurrentPackageId", GetCurrentPackageId);
DECLARE_CRT_EXPORT("FreeLibrary", FreeLibrary);

DECLARE_CRT_EXPORT("LoadLibraryExW", LoadLibraryExW);

DECLARE_CRT_EXPORT("LoadLibraryW", LoadLibraryW);

DECLARE_CRT_EXPORT("GetProcAddress", GetProcAddress);

DECLARE_CRT_EXPORT("GetModuleHandleW", GetModuleHandleW);

DECLARE_CRT_EXPORT("GetModuleHandleA", GetModuleHandleA);

DECLARE_CRT_EXPORT("GetModuleFileNameA", GetModuleFileNameA);

DECLARE_CRT_EXPORT("GetModuleFileNameW", GetModuleFileNameW);

DECLARE_CRT_EXPORT("GetModuleHandleExA", GetModuleHandleExA);

DECLARE_CRT_EXPORT("GetModuleHandleExW", GetModuleHandleExW);
