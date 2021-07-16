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
                                               ULONG ProcessInformationLength) {
    DebugLog("%p", ProcessHandle);
    return 0;
}

STATIC BOOL WINAPI QueryFullProcessImageNameW(HANDLE hProcess,
                                              DWORD dwFlags,
                                              LPWSTR lpExeName,
                                              PDWORD lpdwSize) {
    DebugLog("");
    if (dwFlags == 0)
        lpExeName = L"C:\\nice\\path\\to\\binary.exe";
    else
        lpExeName = L"\\??\\C:\\nice\\path\\to\\binary.exe";
    return true;
}

STATIC BOOL WINAPI GetProcessMitigationPolicy(HANDLE hProcess,
                                              PROCESS_MITIGATION_POLICY MitigationPolicy,
                                              PVOID lpBuffer,
                                              SIZE_T dwLength) {
    DebugLog("%p %hx %p", hProcess, MitigationPolicy, lpBuffer);
    return true;
}

STATIC BOOL WINAPI SetProcessInformation(HANDLE hProcess,
                                         PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                         PVOID ProcessInformation,
                                         DWORD ProcessInformationSize) {
    DebugLog("%p %hx %p", hProcess, ProcessInformationClass, ProcessInformation);
    return true;
}

DECLARE_CRT_EXPORT("QueryFullProcessImageNameW", QueryFullProcessImageNameW);

DECLARE_CRT_EXPORT("NtSetInformationProcess", NtSetInformationProcess);

DECLARE_CRT_EXPORT("GetProcessMitigationPolicy", GetProcessMitigationPolicy);

DECLARE_CRT_EXPORT("SetProcessInformation", SetProcessInformation);
