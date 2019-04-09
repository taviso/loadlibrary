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

STATIC ULONG WINAPI RegisterTraceGuidsW(PVOID RequestAddress,
                                 PVOID RequestContext,
                                 PVOID ControlGuid,
                                 ULONG GuidCount,
                                 PVOID TraceGuidReg,
                                 PVOID MofImagePath,
                                 PVOID MofResourceName,
                                 PVOID RegistrationHandle)
{
    DebugLog("%p, %p, %p, %u, %p, %p, %p, %p",
             RequestAddress,
             RequestContext,
             ControlGuid,
             GuidCount,
             TraceGuidReg,
             MofImagePath,
             MofResourceName,
             RegistrationHandle);

    return STATUS_SUCCESS;
}

STATIC ULONG WINAPI UnregisterTraceGuids(HANDLE RegistrationHandle)
{
    DebugLog("%p", RegistrationHandle);
    return STATUS_SUCCESS;
}

DECLARE_CRT_EXPORT("RegisterTraceGuidsW", RegisterTraceGuidsW);
DECLARE_CRT_EXPORT("UnregisterTraceGuids", UnregisterTraceGuids);
