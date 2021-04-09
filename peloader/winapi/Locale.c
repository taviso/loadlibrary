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

#define MAX_DEFAULTCHAR 2
#define MAX_LEADBYTES 12

typedef struct _cpinfo {
  UINT MaxCharSize;
  BYTE DefaultChar[MAX_DEFAULTCHAR];
  BYTE LeadByte[MAX_LEADBYTES];
} CPINFO, *LPCPINFO;

STATIC UINT GetACP(void)
{
    NOP_FILL();
    DebugLog("");

    return 65001;   // UTF-8
}

STATIC WINAPI BOOL IsValidCodePage(UINT CodePage)
{
    NOP_FILL();
    DebugLog("%u", CodePage);

    return TRUE;
}

STATIC WINAPI BOOL GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)
{
    NOP_FILL();
    DebugLog("%u, %p", CodePage, lpCPInfo);

    memset(lpCPInfo, 0, sizeof *lpCPInfo);

    lpCPInfo->MaxCharSize       = 1;
    lpCPInfo->DefaultChar[0]    = '?';

    return TRUE;
}

STATIC DWORD LocaleNameToLCID(PVOID lpName, DWORD dwFlags)
{
    NOP_FILL();
    DebugLog("%p, %#x", lpName, dwFlags);
    return 0;
}

STATIC WINAPI int LCMapStringW(DWORD Locale, DWORD dwMapFlags, PVOID lpSrcStr, int cchSrc, PVOID lpDestStr, int cchDest)
{
    NOP_FILL();
    DebugLog("%u, %#x, %p, %d, %p, %d", Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);
    return 1;
}

#define LOCALE_NAME_USER_DEFAULT NULL
#define NORM_IGNORENONSPACE 1
#define LCMAP_UPPERCASE 512
STATIC WINAPI int LCMapStringEx(PVOID lpLocaleName, DWORD dwMapFlags, PVOID lpSrcStr, int cchSrc, PVOID lpDestStr, int cchDest, PVOID lpVersionInformation, PVOID lpReserved, PVOID sortHandle)
{
    NOP_FILL();
    DebugLog("%p, %#x, %p, %d, %p, %d, %p, %p, %p", lpLocaleName, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, lpVersionInformation, lpReserved, sortHandle);

    assert(lpLocaleName == LOCALE_NAME_USER_DEFAULT);

    if (lpDestStr == NULL) {
        return cchSrc;
    }

    memcpy(lpDestStr, lpSrcStr, cchDest > cchSrc ? cchSrc : cchDest);

    return cchDest > cchSrc ? cchSrc : cchDest;
}

STATIC WINAPI int GetLocaleInfoEx(LPCWSTR lpLocaleName, DWORD LCType, LPWSTR lpLCData, int cchData)
{
    NOP_FILL();
    DebugLog("%S, %d, %S, %d", lpLocaleName, LCType, lpLCData, cchData);
    return 0;
}

DECLARE_CRT_EXPORT("GetACP", GetACP);
DECLARE_CRT_EXPORT("IsValidCodePage", IsValidCodePage);
DECLARE_CRT_EXPORT("GetCPInfo", GetCPInfo);
DECLARE_CRT_EXPORT("LocaleNameToLCID", LocaleNameToLCID);
DECLARE_CRT_EXPORT("LCMapStringW", LCMapStringW);
DECLARE_CRT_EXPORT("LCMapStringEx", LCMapStringEx);
DECLARE_CRT_EXPORT("GetLocaleInfoEx", GetLocaleInfoEx);
