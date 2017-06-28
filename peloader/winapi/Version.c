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

typedef struct _OSVERSIONINFOEXW {
    ULONG  dwOSVersionInfoSize;
    ULONG  dwMajorVersion;
    ULONG  dwMinorVersion;
    ULONG  dwBuildNumber;
    ULONG  dwPlatformId;
    WCHAR  szCSDVersion[128];
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    UCHAR  wProductType;
    UCHAR  wReserved;
} RTL_OSVERSIONINFOEXW, *PRTL_OSVERSIONINFOEXW;

typedef struct _SYSTEM_INFO {
  WORD      wProcessorArchitecture;
  WORD      wReserved;
  DWORD     dwPageSize;
  PVOID     lpMinimumApplicationAddress;
  PVOID     lpMaximumApplicationAddress;
  PVOID     dwActiveProcessorMask;
  DWORD     dwNumberOfProcessors;
  DWORD     dwProcessorType;
  DWORD     dwAllocationGranularity;
  WORD      wProcessorLevel;
  WORD      wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;

static DWORD WINAPI RtlGetVersion(PRTL_OSVERSIONINFOEXW lpVersionInformation)
{
    if (lpVersionInformation->dwOSVersionInfoSize == sizeof (RTL_OSVERSIONINFOEXW)) {
        DebugLog("%p (RTL_OSVERSIONINFOEXW)", lpVersionInformation);
    } else {
        DebugLog("%p (%u dwOSVersionInfoSize)",
                 lpVersionInformation,
                 lpVersionInformation->dwOSVersionInfoSize);
    }

    // Windows XP
    lpVersionInformation->dwMajorVersion = 5;
    lpVersionInformation->dwMinorVersion = 1;

    return STATUS_SUCCESS;
}

#define PROCESSOR_ARCHITECTURE_INTEL 0

static VOID WINAPI GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
    DebugLog("%p", lpSystemInfo);

    lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    lpSystemInfo->dwPageSize = 0x1000;
}

static DWORD GetSystemDefaultLCID(void)
{
    DebugLog("");
    return 0x0800; // I dunno
}

static NTSTATUS WINAPI NtQuerySystemInformation(DWORD SystemInformationClass,
                                                PVOID SystemInformation,
                                                ULONG SystemInformationLength,
                                                PULONG ReturnLength)
{
    DebugLog("");
    return -1;
}

static BOOL WINAPI GetComputerNameExW(DWORD NameType,
                                      PWCHAR lpBuffer,
                                      PDWORD lpnSize)
{
    DebugLog("");
    return FALSE;
}

static BOOL WINAPI GetProductInfo(DWORD dwOSMajorVersion,
                                  DWORD dwOSMinorVersion,
                                  DWORD dwSpMajorVersion,
                                  DWORD dwSpMinorVersion,
                                  PDWORD pdwReturnedProductType)
{
    DebugLog("");
    *pdwReturnedProductType = 6;
    return TRUE;
}

static DWORD WINAPI GetVersion(void)
{
    DebugLog("");
    return 0x80000000;
}

static DWORD WINAPI GetVersionExA(PRTL_OSVERSIONINFOEXW lpVersionInformation)
{
    DebugLog("");
    return TRUE;
}


DECLARE_CRT_EXPORT("GetVersion", GetVersion);
DECLARE_CRT_EXPORT("GetVersionExA", GetVersionExA);
DECLARE_CRT_EXPORT("RtlGetVersion", RtlGetVersion);
DECLARE_CRT_EXPORT("GetSystemInfo", GetSystemInfo);
DECLARE_CRT_EXPORT("GetSystemDefaultLCID", GetSystemDefaultLCID);
DECLARE_CRT_EXPORT("NtQuerySystemInformation", NtQuerySystemInformation);
DECLARE_CRT_EXPORT("GetComputerNameExW", GetComputerNameExW);
DECLARE_CRT_EXPORT("GetProductInfo", GetProductInfo);
