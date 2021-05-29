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

DECLARE_CRT_EXPORT("AreFileApisANSI", AreFileApisANSI);
//DECLARE_CRT_EXPORT("CompareStringEx", CompareStringEx);
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
DECLARE_CRT_EXPORT("GetProcessInformation", GetProcessInformation);
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
