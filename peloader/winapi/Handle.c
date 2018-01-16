#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
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
#include "strings.h"

STATIC BOOL WINAPI DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, PHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
{
    DebugLog("%p, %p, %p, %p, %#x, %u, %#x", hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);

    // lol i dunno
    *lpTargetHandle = hSourceProcessHandle;
    return TRUE;
}

STATIC UINT WINAPI SetHandleCount(UINT handleCount)
{
    DebugLog("%u", handleCount);
    return handleCount;
}


DECLARE_CRT_EXPORT("DuplicateHandle", DuplicateHandle);
DECLARE_CRT_EXPORT("SetHandleCount", SetHandleCount);
