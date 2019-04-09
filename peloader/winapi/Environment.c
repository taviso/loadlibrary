#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <search.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

#define ERROR_ENVVAR_NOT_FOUND 203

extern void WINAPI SetLastError(DWORD dwErrCode);

WCHAR EnvironmentStrings[] =
    L"ALLUSERSPROFILE=AllUsersProfile\0"
    L"ALLUSERSAPPDATA=AllUsersAppdata\0"
;

STATIC PVOID WINAPI GetEnvironmentStringsW(void)
{
    DebugLog("");

    return EnvironmentStrings;
}

STATIC BOOL WINAPI FreeEnvironmentStringsW(PVOID lpszEnvironmentBlock)
{
    DebugLog("%p", lpszEnvironmentBlock);

    return TRUE;
}

STATIC DWORD WINAPI GetEnvironmentVariableW(PWCHAR lpName, PVOID lpBuffer, DWORD nSize)
{
    char *AnsiName = CreateAnsiFromWide(lpName);

    DebugLog("%p [%s], %p, %u", lpName, AnsiName, lpBuffer, nSize);

    memset(lpBuffer, 0, nSize);

    if (strcmp(AnsiName, "MpAsyncWorkMaxThreads") == 0) {
        memcpy(lpBuffer, L"1", sizeof(L"1"));
    } else if (strcmp(AnsiName, "MP_FOLDERSCAN_THREAD_COUNT") == 0) {
        memcpy(lpBuffer, L"1", sizeof(L"1"));
    } else if (strcmp(AnsiName, "MP_PERSISTEDSTORE_DISABLE") == 0) {
        memcpy(lpBuffer, L"1", sizeof(L"1"));
    } else if (strcmp(AnsiName, "MP_METASTORE_DISABLE") == 0) {
        memcpy(lpBuffer, L"1", sizeof(L"1"));
    } else {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
    }

    free(AnsiName);
    return CountWideChars(lpBuffer);
}

// MPENGINE is very fussy about what ExpandEnvironmentStringsW returns.
STATIC DWORD WINAPI ExpandEnvironmentStringsW(PWCHAR lpSrc, PWCHAR lpDst, DWORD nSize)
{
    PCHAR AnsiString = CreateAnsiFromWide(lpSrc);
    DWORD Result;
    struct {
        PCHAR   Src;
        PWCHAR  Dst;
    } KnownPaths[] = {
        { "%ProgramFiles%", L"C:\\Program Files" },
        { "%AllUsersProfile%", L"C:\\ProgramData" },
        { "%PATH%", L"C:\\Path" },
        { "%windir%", L"C:\\Windows" },
        { "%ProgramFiles(x86)%", L"C:\\Program Files" },
        { "%WINDIR%\\system32\\drivers", L"C:\\WINDOWS\\system32\\drivers" },
        { "%windir%\\temp", L"C:\\WINDOWS\\temp" },
        { "%CommonProgramFiles%", L"C:\\CommonProgramFiles" },
        { NULL },
    };

    DebugLog("%p [%s], %p, %u", lpSrc, AnsiString, lpDst, nSize);

    for (int i = 0; KnownPaths[i].Src; i++) {
        if (strcmp(AnsiString, KnownPaths[i].Src) == 0) {
            Result = CountWideChars(KnownPaths[i].Dst) + 1;
            if (nSize < Result) {
                goto finish;
            }
            memcpy(lpDst, KnownPaths[i].Dst, Result * 2);
            goto finish;
        }
    }

    free(AnsiString);

    if (nSize < CountWideChars(lpSrc) + 1) {
        return CountWideChars(lpSrc) + 1;
    }

    memcpy(lpDst, lpSrc, (1 + CountWideChars(lpSrc)) * 2);

    return CountWideChars(lpSrc) + 1;

finish:
    free(AnsiString);
    return Result;
}

static DWORD WINAPI GetEnvironmentVariableA(PCHAR lpName, PVOID lpBuffer, DWORD nSize)
{
    DebugLog("%s, %p, %u", lpName, lpBuffer, nSize);
    return 0;
}

DECLARE_CRT_EXPORT("GetEnvironmentStringsW", GetEnvironmentStringsW);
DECLARE_CRT_EXPORT("FreeEnvironmentStringsW", FreeEnvironmentStringsW);
DECLARE_CRT_EXPORT("GetEnvironmentVariableW", GetEnvironmentVariableW);
DECLARE_CRT_EXPORT("ExpandEnvironmentStringsW", ExpandEnvironmentStringsW);
DECLARE_CRT_EXPORT("GetEnvironmentVariableA", GetEnvironmentVariableA);
