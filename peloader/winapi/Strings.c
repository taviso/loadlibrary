#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

#define MB_ERR_INVALID_CHARS 8

STATIC int WINAPI MultiByteToWideChar(UINT CodePage, DWORD  dwFlags, PCHAR lpMultiByteStr, int cbMultiByte, PUSHORT lpWideCharStr, int cchWideChar)
{
    size_t i;

    DebugLog("%u, %#x, %p, %u, %p, %u", CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);

    if ((dwFlags & ~MB_ERR_INVALID_CHARS) != 0) {
        LogMessage("Unsupported Conversion Flags %#x", dwFlags);
    }

    if (CodePage != 0 && CodePage != 65001) {
        DebugLog("Unsupported CodePage %u", CodePage);
    }

    if (cbMultiByte == 0)
        return 0;

    if (cbMultiByte == -1)
        cbMultiByte = strlen(lpMultiByteStr) + 1;

    if (cchWideChar == 0)
        return cbMultiByte;

    // cbMultibyte is the number of *bytes* to process.
    // cchWideChar is the number of output *chars* expected.
    if (cbMultiByte > cchWideChar) {
        return 0;
    }

    for (i = 0; i < cbMultiByte; i++) {
        lpWideCharStr[i] = (uint8_t) lpMultiByteStr[i];
        if (dwFlags & MB_ERR_INVALID_CHARS) {
            if (!isascii(lpMultiByteStr[i]) || iscntrl(lpMultiByteStr[i])) {
                lpWideCharStr[i] = '?';
            }
        }
    }

    return i;
}

STATIC int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, PVOID lpWideCharStr, int cchWideChar, PVOID lpMultiByteStr, int cbMultiByte, PVOID lpDefaultChar, PVOID lpUsedDefaultChar)
{
    DebugLog("%u, %#x, %p, %d, %p, %d, %p, %p", CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

    // Process NULL terminated string.
    if (cchWideChar == -1) {
        char *ansi = CreateAnsiFromWide(lpWideCharStr);
        // This really can happen
        if (ansi == NULL) {
            return 0;
        }
        DebugLog("cchWideChar == -1, Ansi: [%s]", ansi);
        if (lpMultiByteStr && strlen(ansi) < cbMultiByte) {
            strcpy(lpMultiByteStr, ansi);
            free(ansi);
            return strlen(lpMultiByteStr) + 1;
        }
        free(ansi);
        return 0;
    }

    DebugLog("Don't Support This cchWideChar");

    return 0;
}

STATIC BOOL GetStringTypeW(DWORD dwInfoType, PUSHORT lpSrcStr, int cchSrc, PUSHORT lpCharType)
{
    //DebugLog("%u, %p, %d, %p", dwInfoType, lpSrcStr, cchSrc, lpCharType);

    memset(lpCharType, 1, cchSrc * sizeof(USHORT));

    return FALSE;
}

STATIC VOID WINAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PWCHAR SourceString)
{
    DestinationString->Length = CountWideChars(SourceString) * 2;
    DestinationString->MaximumLength = DestinationString->Length;
    DestinationString->Buffer = SourceString;
}

DECLARE_CRT_EXPORT("MultiByteToWideChar", MultiByteToWideChar);
DECLARE_CRT_EXPORT("WideCharToMultiByte", WideCharToMultiByte);
DECLARE_CRT_EXPORT("GetStringTypeW", GetStringTypeW);
DECLARE_CRT_EXPORT("RtlInitUnicodeString", RtlInitUnicodeString);
