#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

// I don't implement threads, so critical sections are easy.

STATIC VOID WINAPI DeleteCriticalSection(PVOID lpCriticalSection)
{
    NOP_FILL();
    return;
}

STATIC VOID WINAPI EnterCriticalSection(PVOID lpCriticalSection)
{
    NOP_FILL();
    return;
}

STATIC VOID WINAPI LeaveCriticalSection(PVOID lpCriticalSection)
{
    NOP_FILL();
    return;
}

STATIC BOOL WINAPI InitializeCriticalSectionAndSpinCount(PVOID lpCriticalSection, DWORD dwSpinCount)
{
    NOP_FILL();
    return TRUE;
}

STATIC BOOL WINAPI InitializeCriticalSectionEx(PVOID lpCriticalSection, DWORD dwSpinCount, DWORD Flags)
{
    NOP_FILL();
    return TRUE;
}

STATIC VOID WINAPI InitializeCriticalSection(PVOID lpCriticalSection)
{
    NOP_FILL();
    return;
}

DECLARE_CRT_EXPORT("DeleteCriticalSection", DeleteCriticalSection);
DECLARE_CRT_EXPORT("LeaveCriticalSection", LeaveCriticalSection);
DECLARE_CRT_EXPORT("EnterCriticalSection", EnterCriticalSection);
DECLARE_CRT_EXPORT("InitializeCriticalSectionAndSpinCount", InitializeCriticalSectionAndSpinCount);
DECLARE_CRT_EXPORT("InitializeCriticalSectionEx", InitializeCriticalSectionEx);
DECLARE_CRT_EXPORT("InitializeCriticalSection", InitializeCriticalSection);
