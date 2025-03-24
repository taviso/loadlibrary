#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <search.h>
#include <string.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

STATIC NTSTATUS WINAPI NtSetInformationProcess(HANDLE ProcessHandle,
                                               PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                               PVOID ProcessInformation,
                                               ULONG ProcessInformationLength)
{
    DebugLog("%p", ProcessHandle);
    return 0;
}

STATIC BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle,
                                    ACCESS_MASK DesiredAccess,
                                    PHANDLE TokenHandle)
{
    DebugLog("%p", ProcessHandle);
    return FALSE;
}

STATIC BOOL WINAPI GetExitCodeProcess(HANDLE ProcessHandle,
                                    PDWORD ExitCode)
{
DebugLog("%p", ProcessHandle);
    //Status Pending
    *ExitCode = 0x103;
    return TRUE;
}

STATIC BOOL WINAPI QueryFullProcessImageNameW(HANDLE ProcessHandle,
                                                DWORD Flags,
                                                LPWSTR ExeName,
                                                PDWORD Size)
{
    DebugLog("Handle: %p, Size: %d", ProcessHandle, *Size);
    ExeName = L"MsMpEng.exe";
    *Size = 11;
    return TRUE;
}

DECLARE_CRT_EXPORT("NtSetInformationProcess", NtSetInformationProcess);
DECLARE_CRT_EXPORT("OpenProcessToken", OpenProcessToken);
DECLARE_CRT_EXPORT("GetExitCodeProcess", GetExitCodeProcess);
DECLARE_CRT_EXPORT("QueryFullProcessImageNameW", QueryFullProcessImageNameW);