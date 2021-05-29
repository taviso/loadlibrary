#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

extern void WINAPI SetLastError(DWORD dwErrCode);

static HANDLE WINAPI CreateEventW(PVOID lpEventAttributes, BOOL bManualReset, BOOL bInitialState, PWCHAR lpName)
{
    NOP_FILL();
    char *AnsiName;
#ifndef NDEBUG
    AnsiName = lpName ? CreateAnsiFromWide(lpName) : NULL;
#else
    AnsiName = NULL;
#endif

    DebugLog("%p, %u, %u, %p [%s]", lpEventAttributes, bManualReset, bInitialState, lpName, AnsiName);

    free(AnsiName);

    SetLastError(0);

    return (HANDLE) 'EVNT';
}

static BOOL WINAPI SetEvent(HANDLE hEvent)
{
    NOP_FILL();
    DebugLog("%p", hEvent);
    return TRUE;
}

static BOOL WINAPI ResetEvent(HANDLE hEvent)
{
    NOP_FILL();
    DebugLog("%p", hEvent);
    return TRUE;
}

STATIC DWORD WINAPI EventSetInformation(HANDLE RegHandle,
                                        EVENT_INFO_CLASS InformationClass,
                                        PVOID EventInformation,
                                        ULONG InformationLength) {
    NOP_FILL();
    DebugLog("");
    return STATUS_SUCCESS;
}

STATIC ULONG WINAPI EventUnregister(HANDLE RegHandle) {
    NOP_FILL();
    DebugLog("");
    return STATUS_SUCCESS;
}

DECLARE_CRT_EXPORT("CreateEventW", CreateEventW, 4);
DECLARE_CRT_EXPORT("SetEvent", SetEvent, 1);
DECLARE_CRT_EXPORT("ResetEvent", ResetEvent, 1);
DECLARE_CRT_EXPORT("EventSetInformation", EventSetInformation, 4);
DECLARE_CRT_EXPORT("EventUnregister", EventUnregister, 1);
