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

static const uint16_t kTempPath[] = L".\\FAKETEMP\\";

DWORD WINAPI GetTempPathW(DWORD nBufferLength, PVOID lpBuffer)
{
    DebugLog("%u, %p", nBufferLength, lpBuffer);

    memcpy(lpBuffer, kTempPath, sizeof(kTempPath));

    return sizeof(kTempPath) - 2;
}

DWORD WINAPI GetLogicalDrives(void)
{
    DebugLog("");

    return 1 << 2;
}

#define DRIVE_FIXED 3

UINT WINAPI GetDriveTypeW(PWCHAR lpRootPathName)
{
    char *path = CreateAnsiFromWide(lpRootPathName);
    DebugLog("%p [%s]", lpRootPathName, path);
    free(path);
    return DRIVE_FIXED;
}

DWORD WINAPI GetLongPathNameA(LPCSTR lpszShortPath,
                              LPSTR lpszLongPath,
                              DWORD cchBuffer)
{
    // For now we just return the 8.3 format path as the long path
    if (cchBuffer > strlen(lpszShortPath)) {
        memcpy(lpszLongPath, lpszShortPath, sizeof(lpszShortPath));
    }

    return strlen(lpszShortPath);
}

DWORD WINAPI GetLongPathNameW(LPCWSTR lpszShortPath,
                              LPWSTR lpszLongPath,
                              DWORD cchBuffer)
{
    // For now we just return the 8.3 format path as the long path
    if (cchBuffer > CountWideChars(lpszShortPath)) {
        memcpy(lpszLongPath, lpszShortPath, CountWideChars(lpszShortPath) * sizeof(WCHAR));
    }

    return CountWideChars(lpszShortPath);
}

DECLARE_CRT_EXPORT("GetTempPathW", GetTempPathW);
DECLARE_CRT_EXPORT("GetLogicalDrives", GetLogicalDrives);
DECLARE_CRT_EXPORT("GetDriveTypeW", GetDriveTypeW);
DECLARE_CRT_EXPORT("GetLongPathNameA", GetLongPathNameA);
DECLARE_CRT_EXPORT("GetLongPathNameW", GetLongPathNameW);
