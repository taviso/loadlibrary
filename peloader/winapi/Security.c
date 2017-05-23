#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

BOOL WINAPI LookupPrivilegeValueW(PVOID lpSystemName, PVOID lpName, PVOID lpLuid)
{
    DebugLog("%p, %p, %p", lpSystemName, lpName, lpLuid);

    return FALSE;
}

DECLARE_CRT_EXPORT("LookupPrivilegeValueW", LookupPrivilegeValueW);
