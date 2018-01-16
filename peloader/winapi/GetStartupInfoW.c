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

typedef struct _STARTUPINFO {
  DWORD  cb;
  PVOID lpReserved;
  PVOID lpDesktop;
  PVOID lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  PVOID  lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFO, *LPSTARTUPINFO;


STATIC void WINAPI GetStartupInfoA(LPSTARTUPINFO lpStartupInfo)
{
    memset(lpStartupInfo, 0, sizeof *lpStartupInfo);

    DebugLog("GetStartupInfoA(%p)", lpStartupInfo);
}


STATIC void WINAPI GetStartupInfoW(LPSTARTUPINFO lpStartupInfo)
{
    memset(lpStartupInfo, 0, sizeof *lpStartupInfo);

    DebugLog("GetStartupInfoW(%p)", lpStartupInfo);
}

STATIC PVOID WINAPI GetCommandLineA(void)
{
    DebugLog("");
    return "totallylegit.exe notfake very real";
}

STATIC PVOID WINAPI GetCommandLineW(void)
{
    DebugLog("");
    return L"totallylegit.exe notfake very real";
}

DECLARE_CRT_EXPORT("GetStartupInfoA", GetStartupInfoA);
DECLARE_CRT_EXPORT("GetStartupInfoW", GetStartupInfoW);
DECLARE_CRT_EXPORT("GetCommandLineA", GetCommandLineA);
DECLARE_CRT_EXPORT("GetCommandLineW", GetCommandLineW);
