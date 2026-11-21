#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

/* Here goes all the APIs requested by GetProcAddress in order to quickly identify which one is being called and
 * needs to be implemented
 */

STATIC PVOID WINAPI AreFileApisANSI() {
    DebugLog("");
    return 0;
}

STATIC PVOID WINAPI CompareStringEx() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI EnumSystemLocalesEx() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetDateFormatEx() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetTimeFormatEx() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI IsValidLocaleName() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI LCIDToLocaleName() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI CancelSynchronousIo() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI CreateSymbolicLinkW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI DeleteProcThreadAttributeList() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI FindFirstFileNameW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI FindNextFileNameW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetFileInformationByHandleEx() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetFinalPathNameByHandleW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetFirmwareEnvironmentVariableA() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetFirmwareEnvironmentVariableExW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetFirmwareType() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetProcessInformation() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetThreadInformation() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetUserDefaultLocaleName() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI InitializeProcThreadAttributeList() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32EnumPageFilesW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32EnumProcessModules() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32EnumProcesses() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32GetMappedFileNameW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32GetModuleBaseNameW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32GetModuleFileNameExW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32GetModuleInformation() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32GetProcessImageFileNameW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32GetProcessMemoryInfo() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI K32QueryWorkingSetEx() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI PrefetchVirtualMemory() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI SetThreadInformation() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI TryAcquireSRWLockExclusive() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI UpdateProcThreadAttribute() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC long WINAPI EventRegister(PVOID ProviderId,
                                 PVOID EnableCallback,
                                 PVOID CallbackContext,
                                 HANDLE RegHandle) {
    DebugLog("");
    return 0;
}

STATIC PVOID WINAPI EventWriteTransfer() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI NotifyServiceStatusChangeW() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI RegDisableReflectionKey() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI RegEnableReflectionKey() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI RegQueryReflectionKey() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetTempPath2W() {
    DebugLog("Not implemented.");
    exit(1);
}

STATIC BOOL WINAPI InitializeSecurityDescriptor(
  PVOID pSecurityDescriptor,
  DWORD                dwRevision
){
    DebugLog("Returning success from InitializeSecurityDescriptor");
    return 1;
};

STATIC BOOL WINAPI SetSecurityDescriptorDacl(
  PVOID pSecurityDescriptor,
  BOOL  bDaclPresent,
  PVOID pDacl,
  BOOL                 bDaclDefaulted
){

    DebugLog("Returning success from SetSecurityDescriptorDacl");
    return 1;
};


STATIC DWORD WINAPI RegGetValueA(
  PVOID   hkey,
  LPCSTR  lpSubKey,
  LPCSTR  lpValue,
  DWORD   dwFlags,
  LPDWORD pdwType,
  PVOID   pvData,
  LPDWORD pcbData
){
    DebugLog(lpValue);
    if (pvData != NULL && !strcmp(lpValue, "CurrentVersion") && *pcbData >= 4){
        strcpy(pvData, "6.3");
        *pcbData=4;
        return 0;
    }
    char* prod_name="Windows Server 2022 Standard";
    size_t prod_name_len=strlen(prod_name);
    if (pvData != NULL && !strcmp(lpValue, "ProductName") && *pcbData >= prod_name_len){
        strcpy(pvData, prod_name);
        *pcbData=prod_name_len;
        return 0;
    }

    return 1;
}

typedef struct _JOBOBJECT_BASIC_LIMIT_INFORMATION {
  LARGE_INTEGER PerProcessUserTimeLimit;
  LARGE_INTEGER PerJobUserTimeLimit;
  DWORD         LimitFlags;
  SIZE_T        MinimumWorkingSetSize;
  SIZE_T        MaximumWorkingSetSize;
  DWORD         ActiveProcessLimit;
  ULONG_PTR     Affinity;
  DWORD         PriorityClass;
  DWORD         SchedulingClass;
} JOBOBJECT_BASIC_LIMIT_INFORMATION, *PJOBOBJECT_BASIC_LIMIT_INFORMATION;

typedef struct _IO_COUNTERS {
  ULONGLONG ReadOperationCount;
  ULONGLONG WriteOperationCount;
  ULONGLONG OtherOperationCount;
  ULONGLONG ReadTransferCount;
  ULONGLONG WriteTransferCount;
  ULONGLONG OtherTransferCount;
} IO_COUNTERS;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
  JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
  IO_COUNTERS                       IoInfo;
  SIZE_T                            ProcessMemoryLimit;
  SIZE_T                            JobMemoryLimit;
  SIZE_T                            PeakProcessMemoryUsed;
  SIZE_T                            PeakJobMemoryUsed;
} JOBOBJECT_EXTENDED_LIMIT_INFORMATION, *PJOBOBJECT_EXTENDED_LIMIT_INFORMATION;

STATIC WINAPI BOOL QueryInformationJobObject(
  HANDLE             hJob,
  DWORD JobObjectInformationClass,
  LPVOID             lpJobObjectInformation,
  DWORD              cbJobObjectInformationLength,
  LPDWORD            lpReturnLength
){
  DebugLog("%d %d", hJob, JobObjectInformationClass);
  if ( JobObjectInformationClass == 9) {
    PJOBOBJECT_EXTENDED_LIMIT_INFORMATION info = (PJOBOBJECT_EXTENDED_LIMIT_INFORMATION)lpJobObjectInformation;

    info->BasicLimitInformation.LimitFlags = 0;
    info->PeakProcessMemoryUsed=0x41;
    info->PeakJobMemoryUsed=0x41;
  }
  return true;
}

DECLARE_CRT_EXPORT("QueryInformationJobObject", QueryInformationJobObject);
DECLARE_CRT_EXPORT("RegGetValueA", RegGetValueA);
DECLARE_CRT_EXPORT("SetSecurityDescriptorDacl", SetSecurityDescriptorDacl);
DECLARE_CRT_EXPORT("InitializeSecurityDescriptor", InitializeSecurityDescriptor);
DECLARE_CRT_EXPORT("AreFileApisANSI", AreFileApisANSI);
DECLARE_CRT_EXPORT("CompareStringEx", CompareStringEx);
DECLARE_CRT_EXPORT("GetTempPath2W", GetTempPath2W);
DECLARE_CRT_EXPORT("EnumSystemLocalesEx", EnumSystemLocalesEx);

DECLARE_CRT_EXPORT("GetDateFormatEx", GetDateFormatEx);

DECLARE_CRT_EXPORT("GetTimeFormatEx", GetTimeFormatEx);

DECLARE_CRT_EXPORT("GetUserDefaultLocaleName", GetUserDefaultLocaleName);

DECLARE_CRT_EXPORT("IsValidLocaleName", IsValidLocaleName);

DECLARE_CRT_EXPORT("LCIDToLocaleName", LCIDToLocaleName);

DECLARE_CRT_EXPORT("CancelSynchronousIo", CancelSynchronousIo);

DECLARE_CRT_EXPORT("CreateSymbolicLinkW", CreateSymbolicLinkW);

DECLARE_CRT_EXPORT("DeleteProcThreadAttributeList", DeleteProcThreadAttributeList);

DECLARE_CRT_EXPORT("FindFirstFileNameW", FindFirstFileNameW);

DECLARE_CRT_EXPORT("FindNextFileNameW", FindNextFileNameW);

DECLARE_CRT_EXPORT("GetFileInformationByHandleEx", GetFileInformationByHandleEx);

DECLARE_CRT_EXPORT("GetFinalPathNameByHandleW", GetFinalPathNameByHandleW);

DECLARE_CRT_EXPORT("GetFirmwareEnvironmentVariableA", GetFirmwareEnvironmentVariableA);

DECLARE_CRT_EXPORT("GetFirmwareEnvironmentVariableExW", GetFirmwareEnvironmentVariableExW);

DECLARE_CRT_EXPORT("GetFirmwareType", GetFirmwareType);

/* On x86, report this optional API as unavailable rather than advertising
 * the diagnostic stub that terminates the process when called. */
#ifdef __x86_64__
DECLARE_CRT_EXPORT("GetProcessInformation", GetProcessInformation);
#endif

DECLARE_CRT_EXPORT("GetThreadInformation", GetThreadInformation);

DECLARE_CRT_EXPORT("InitializeProcThreadAttributeList", InitializeProcThreadAttributeList);

DECLARE_CRT_EXPORT("K32EnumPageFilesW", K32EnumPageFilesW);

DECLARE_CRT_EXPORT("K32EnumProcessModules", K32EnumProcessModules);

DECLARE_CRT_EXPORT("K32EnumProcesses", K32EnumProcesses);

DECLARE_CRT_EXPORT("K32GetMappedFileNameW", K32GetMappedFileNameW);

DECLARE_CRT_EXPORT("K32GetModuleBaseNameW", K32GetModuleBaseNameW);

DECLARE_CRT_EXPORT("K32GetModuleFileNameExW", K32GetModuleFileNameExW);

DECLARE_CRT_EXPORT("K32GetModuleInformation", K32GetModuleInformation);

DECLARE_CRT_EXPORT("K32GetProcessImageFileNameW", K32GetProcessImageFileNameW);

DECLARE_CRT_EXPORT("K32GetProcessMemoryInfo", K32GetProcessMemoryInfo);

DECLARE_CRT_EXPORT("K32QueryWorkingSetEx", K32QueryWorkingSetEx);

DECLARE_CRT_EXPORT("PrefetchVirtualMemory", PrefetchVirtualMemory);

DECLARE_CRT_EXPORT("SetThreadInformation", SetThreadInformation);

DECLARE_CRT_EXPORT("TryAcquireSRWLockExclusive", TryAcquireSRWLockExclusive);

DECLARE_CRT_EXPORT("UpdateProcThreadAttribute", UpdateProcThreadAttribute);

DECLARE_CRT_EXPORT("EventRegister", EventRegister);

DECLARE_CRT_EXPORT("EventWriteTransfer", EventWriteTransfer);

DECLARE_CRT_EXPORT("NotifyServiceStatusChangeW", NotifyServiceStatusChangeW);

DECLARE_CRT_EXPORT("RegDisableReflectionKey", RegDisableReflectionKey);

DECLARE_CRT_EXPORT("RegEnableReflectionKey", RegEnableReflectionKey);

DECLARE_CRT_EXPORT("RegQueryReflectionKey", RegQueryReflectionKey);
