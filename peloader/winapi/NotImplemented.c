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
    NOP_FILL();
    DebugLog("");
    return 0;
}
STATIC PVOID WINAPI CompareStringEx() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI EnumSystemLocalesEx() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetDateFormatEx() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetTimeFormatEx() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI IsValidLocaleName() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI LCIDToLocaleName() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI CancelSynchronousIo() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI CreateSymbolicLinkW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI DeleteProcThreadAttributeList() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI FindFirstFileNameW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI FindNextFileNameW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetFileInformationByHandleEx() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetFinalPathNameByHandleW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetFirmwareEnvironmentVariableA() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetFirmwareEnvironmentVariableExW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetFirmwareType() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetProcessInformation() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}

STATIC PVOID WINAPI GetThreadInformation() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI GetUserDefaultLocaleName() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI InitializeProcThreadAttributeList() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32EnumPageFilesW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32EnumProcessModules() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32EnumProcesses() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32GetMappedFileNameW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32GetModuleBaseNameW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32GetModuleFileNameExW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32GetModuleInformation() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32GetProcessImageFileNameW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32GetProcessMemoryInfo() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI K32QueryWorkingSetEx() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI PrefetchVirtualMemory() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI SetThreadInformation() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI TryAcquireSRWLockExclusive() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI UpdateProcThreadAttribute() {
    NOP_FILL();
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
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI NotifyServiceStatusChangeW() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI RegDisableReflectionKey() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI RegEnableReflectionKey() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}
STATIC PVOID WINAPI RegQueryReflectionKey() {
    NOP_FILL();
    DebugLog("Not implemented.");
    exit(1);
}

DECLARE_CRT_EXPORT("AreFileApisANSI", AreFileApisANSI, 0);
//DECLARE_CRT_EXPORT("CompareStringEx", CompareStringEx, 0);
DECLARE_CRT_EXPORT("EnumSystemLocalesEx", EnumSystemLocalesEx, 0);
DECLARE_CRT_EXPORT("GetDateFormatEx", GetDateFormatEx, 0);
DECLARE_CRT_EXPORT("GetTimeFormatEx", GetTimeFormatEx, 0);
DECLARE_CRT_EXPORT("GetUserDefaultLocaleName", GetUserDefaultLocaleName, 0);
DECLARE_CRT_EXPORT("IsValidLocaleName", IsValidLocaleName, 0);
DECLARE_CRT_EXPORT("LCIDToLocaleName", LCIDToLocaleName, 0);
DECLARE_CRT_EXPORT("CancelSynchronousIo", CancelSynchronousIo, 0);
DECLARE_CRT_EXPORT("CreateSymbolicLinkW", CreateSymbolicLinkW, 0);
DECLARE_CRT_EXPORT("DeleteProcThreadAttributeList", DeleteProcThreadAttributeList, 0);
DECLARE_CRT_EXPORT("FindFirstFileNameW", FindFirstFileNameW, 0);
DECLARE_CRT_EXPORT("FindNextFileNameW", FindNextFileNameW, 0);
DECLARE_CRT_EXPORT("GetFileInformationByHandleEx", GetFileInformationByHandleEx, 0);
DECLARE_CRT_EXPORT("GetFinalPathNameByHandleW", GetFinalPathNameByHandleW, 0);
DECLARE_CRT_EXPORT("GetFirmwareEnvironmentVariableA", GetFirmwareEnvironmentVariableA, 0);
DECLARE_CRT_EXPORT("GetFirmwareEnvironmentVariableExW", GetFirmwareEnvironmentVariableExW, 0);
DECLARE_CRT_EXPORT("GetFirmwareType", GetFirmwareType, 0);
DECLARE_CRT_EXPORT("GetProcessInformation", GetProcessInformation, 0);
DECLARE_CRT_EXPORT("GetThreadInformation", GetThreadInformation, 0);
DECLARE_CRT_EXPORT("InitializeProcThreadAttributeList", InitializeProcThreadAttributeList, 0);
DECLARE_CRT_EXPORT("K32EnumPageFilesW", K32EnumPageFilesW, 0);
DECLARE_CRT_EXPORT("K32EnumProcessModules", K32EnumProcessModules, 0);
DECLARE_CRT_EXPORT("K32EnumProcesses", K32EnumProcesses, 0);
DECLARE_CRT_EXPORT("K32GetMappedFileNameW", K32GetMappedFileNameW, 0);
DECLARE_CRT_EXPORT("K32GetModuleBaseNameW", K32GetModuleBaseNameW, 0);
DECLARE_CRT_EXPORT("K32GetModuleFileNameExW", K32GetModuleFileNameExW, 0);
DECLARE_CRT_EXPORT("K32GetModuleInformation", K32GetModuleInformation, 0);
DECLARE_CRT_EXPORT("K32GetProcessImageFileNameW", K32GetProcessImageFileNameW, 0);
DECLARE_CRT_EXPORT("K32GetProcessMemoryInfo", K32GetProcessMemoryInfo, 0);
DECLARE_CRT_EXPORT("K32QueryWorkingSetEx", K32QueryWorkingSetEx, 0);
DECLARE_CRT_EXPORT("PrefetchVirtualMemory", PrefetchVirtualMemory, 0);
DECLARE_CRT_EXPORT("SetThreadInformation", SetThreadInformation, 0);
DECLARE_CRT_EXPORT("TryAcquireSRWLockExclusive", TryAcquireSRWLockExclusive, 0);
DECLARE_CRT_EXPORT("UpdateProcThreadAttribute", UpdateProcThreadAttribute, 0);
DECLARE_CRT_EXPORT("EventRegister", EventRegister, 0);
DECLARE_CRT_EXPORT("EventWriteTransfer", EventWriteTransfer, 0);
DECLARE_CRT_EXPORT("NotifyServiceStatusChangeW", NotifyServiceStatusChangeW, 0);
DECLARE_CRT_EXPORT("RegDisableReflectionKey", RegDisableReflectionKey, 0);
DECLARE_CRT_EXPORT("RegEnableReflectionKey", RegEnableReflectionKey, 0);
DECLARE_CRT_EXPORT("RegQueryReflectionKey", RegQueryReflectionKey, 0);
