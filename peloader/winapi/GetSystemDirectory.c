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

static uint16_t SystemDirectory[] = L"C:\\SYSTEM32\\";

STATIC UINT WINAPI GetSystemDirectoryW(PWCHAR Buffer, UINT uSize)
{
    DebugLog("%p, %u", Buffer, uSize);

    // Srsly?!
    if (uSize >= ARRAY_SIZE(SystemDirectory)) {
        memcpy(Buffer, SystemDirectory, sizeof(SystemDirectory));
        return ARRAY_SIZE(SystemDirectory) - 1;
    } else {
        return ARRAY_SIZE(SystemDirectory);
    }
}

STATIC UINT WINAPI GetSystemWindowsDirectoryW(PWCHAR Buffer, UINT uSize)
{
    DebugLog("%p, %u", Buffer, uSize);

    // Srsly?!
    if (uSize >= ARRAY_SIZE(SystemDirectory)) {
        memcpy(Buffer, SystemDirectory, sizeof(SystemDirectory));
        return ARRAY_SIZE(SystemDirectory) - 1;
    } else {
        return ARRAY_SIZE(SystemDirectory);
    }
}

STATIC UINT WINAPI GetSystemWow64DirectoryW(PWCHAR lpBuffer, UINT uSize)
{
    DebugLog("%p, %u", lpBuffer, uSize);
    return 0;
}


DECLARE_CRT_EXPORT("GetSystemDirectoryW", GetSystemDirectoryW);
DECLARE_CRT_EXPORT("GetSystemWindowsDirectoryW", GetSystemWindowsDirectoryW);
DECLARE_CRT_EXPORT("GetSystemWow64DirectoryW", GetSystemWow64DirectoryW);
