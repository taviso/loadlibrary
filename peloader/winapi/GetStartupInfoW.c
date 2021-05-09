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
    NOP_FILL();
    memset(lpStartupInfo, 0, sizeof *lpStartupInfo);

    DebugLog("GetStartupInfoA(%p)", lpStartupInfo);

    return;
}


STATIC void WINAPI GetStartupInfoW(LPSTARTUPINFO lpStartupInfo)
{
    NOP_FILL();
    memset(lpStartupInfo, 0, sizeof *lpStartupInfo);

    DebugLog("GetStartupInfoW(%p)", lpStartupInfo);

    return;
}

STATIC PVOID WINAPI GetCommandLineA(void)
{
    NOP_FILL();
    DebugLog("");
    return "totallylegit.exe notfake very real";
}

STATIC PVOID WINAPI GetCommandLineW(void)
{
    NOP_FILL();
    DebugLog("");
    return L"totallylegit.exe notfake very real";
}

DECLARE_CRT_EXPORT("GetStartupInfoA", GetStartupInfoA, 1);
DECLARE_CRT_EXPORT("GetStartupInfoW", GetStartupInfoW, 1);
DECLARE_CRT_EXPORT("GetCommandLineA", GetCommandLineA, 0);
DECLARE_CRT_EXPORT("GetCommandLineW", GetCommandLineW, 0);
