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

STATIC DWORD LastError;

STATIC DWORD WINAPI GetLastError(void)
{
    DebugLog("GetLastError() => %#x", LastError);

    return LastError;
}

void WINAPI SetLastError(DWORD dwErrCode)
{
    //DebugLog("SetLastError(%#x)", dwErrCode);
    LastError = dwErrCode;
}

DECLARE_CRT_EXPORT("GetLastError", GetLastError);
DECLARE_CRT_EXPORT("SetLastError", SetLastError);
