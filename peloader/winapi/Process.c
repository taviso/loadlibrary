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

STATIC HANDLE WINAPI OpenProcess(DWORD DesiredAccess, BOOL InheritHandle, DWORD ProcessId)
{
    DebugLog("%#x, %d, %u", DesiredAccess, InheritHandle, ProcessId);
    return (HANDLE) 'PROC';
}

STATIC DWORD WINAPI GetProcessId(HANDLE Process)
{
    DebugLog("%p", Process);
    return 0x1337;
}

STATIC BOOL WINAPI IsWow64Process(HANDLE Process, BOOL *Wow64Process)
{
    DebugLog("%p, %p", Process, Wow64Process);

    // Pretend to be a native 32-bit process.
    *Wow64Process = FALSE;
    return TRUE;
}

DECLARE_CRT_EXPORT("IsWow64Process", IsWow64Process);
DECLARE_CRT_EXPORT("OpenProcess", OpenProcess);
DECLARE_CRT_EXPORT("GetProcessId", GetProcessId);
DECLARE_CRT_EXPORT("NtSetInformationProcess", NtSetInformationProcess);
DECLARE_CRT_EXPORT("OpenProcessToken", OpenProcessToken);
DECLARE_CRT_EXPORT("GetExitCodeProcess", GetExitCodeProcess);
DECLARE_CRT_EXPORT("QueryFullProcessImageNameW", QueryFullProcessImageNameW);