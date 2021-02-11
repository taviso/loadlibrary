#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "Files.h"
#include "subhook.h"
#include "winapi_hook.h"


static HANDLE WINAPI MyFindFirstFileW(PWCHAR lpFileName, PVOID lpFindFileData)
{
    DebugLog("%p, %p", lpFileName, lpFindFileData);

    DisableHook("FindFirstFileW");

    FindFirstFileW(lpFileName, lpFindFileData);

    EnableHook("FindFirstFileW");

    SetLastError(ERROR_FILE_NOT_FOUND);

    return INVALID_HANDLE_VALUE;
}

ADD_CUSTOM_HOOK("FindFirstFileW", FindFirstFileW, MyFindFirstFileW);
