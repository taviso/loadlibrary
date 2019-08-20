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
    DebugLog("%p", hEvent);
    return TRUE;
}

static BOOL WINAPI ResetEvent(HANDLE hEvent)
{
    DebugLog("%p", hEvent);
    return TRUE;
}

DECLARE_CRT_EXPORT("CreateEventW", CreateEventW);
DECLARE_CRT_EXPORT("SetEvent", SetEvent);
DECLARE_CRT_EXPORT("ResetEvent", ResetEvent);
