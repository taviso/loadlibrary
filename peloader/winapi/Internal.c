#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

void WINAPI RtlAcquirePebLock(void) {
    DebugLog("");
    return;
}

void WINAPI RtlReleasePebLock(void) {
    DebugLog("");
    return;
}

NTSTATUS WINAPI LdrGetDllHandle(PWCHAR pwPath, PVOID unused, PUNICODE_STRING ModuleFileName, PHANDLE pHModule) {
    DebugLog("%S %p %p %p", pwPath, unused, ModuleFileName, pHModule);
    pHModule = (HANDLE) 'LDRP';
    return 0;
}

NTSTATUS WINAPI EtwRegister(PVOID ProvideId, PVOID EnableCallback, PVOID CallbackContext, PVOID RegHandle) {
    DebugLog("");
    return 0;
}

NTSTATUS WINAPI EtwUnregister(HANDLE RegHandle) {
    DebugLog("");
    return 0;
}

ULONG WINAPI EtwEventWrite(HANDLE RegHAndle, PVOID EventDescriptor, ULONG UserDataCount, PVOID UserData, PVOID a5) {
    DebugLog("");
    return 0;
}

static NTSTATUS WINAPI LdrLoadDll(PWCHAR PathToFile,
                                  ULONG Flags,
                                  PUNICODE_STRING ModuleFilename,
                                  PHANDLE ModuleHandle) {
    char *PathToFileA = CreateAnsiFromWide(PathToFile);
    char *ModuleFilenameA = CreateAnsiFromWide(ModuleFilename->Buffer);

    DebugLog("%p [%s], %p [%s], %p, %#x", PathToFile, PathToFileA, ModuleFilename, ModuleFilenameA, ModuleHandle, Flags);

    *ModuleHandle = (HANDLE) 'LOAD';

    free(PathToFileA);
    free(ModuleFilenameA);

    return 0;
}

static NTSTATUS WINAPI LdrUnloadDll(HANDLE ModuleHandle) {
    DebugLog("%p", ModuleHandle);

    return 0;
}

static NTSTATUS WINAPI LdrGetProcedureAddress(HMODULE Module,
                                              PANSI_STRING Name,
                                              WORD Ordinal,
                                              PVOID *Address) {
    DebugLog("%p %s %hu %p", Module, Name->buf, Ordinal, Address);

    // Recognizable value to crash on.
    *Address = (PVOID) 'LDRZ';

    // Search if the requested function has been already exported.
    ENTRY e = {Name->buf, NULL}, *ep;
    hsearch_r(e, FIND, &ep, &crtexports);

    // If found, store the pointer and return.
    if (ep != NULL) {
        *Address = ep->data;
        return 0;
    }

    if (strcmp(Name->buf, "EtwEventRegister") == 0) {
        *Address = EtwRegister;
    }
    if (strcmp(Name->buf, "EtwEventUnregister") == 0) {
        *Address = EtwUnregister;
    }
    if (strcmp(Name->buf, "EtwEventWrite") == 0) {
        *Address = EtwEventWrite;
    }

    return 0;
}

DECLARE_CRT_EXPORT("RtlAcquirePebLock", RtlAcquirePebLock);

DECLARE_CRT_EXPORT("RtlReleasePebLock", RtlReleasePebLock);

DECLARE_CRT_EXPORT("LdrGetDllHandle", LdrGetDllHandle);

DECLARE_CRT_EXPORT("LdrLoadDll", LdrLoadDll);

DECLARE_CRT_EXPORT("LdrUnloadDll", LdrUnloadDll);

DECLARE_CRT_EXPORT("LdrGetProcedureAddress", LdrGetProcedureAddress);
