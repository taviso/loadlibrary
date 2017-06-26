#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

STATIC VOID WINAPI InitializeSListHead(PVOID ListHead)
{
    DebugLog("%p", ListHead);
}

STATIC PVOID WINAPI InterlockedFlushSList(PVOID ListHead)
{
    DebugLog("%p", ListHead);
    return NULL;
}

DECLARE_CRT_EXPORT("InitializeSListHead", InitializeSListHead);
DECLARE_CRT_EXPORT("InterlockedFlushSList", InterlockedFlushSList);
