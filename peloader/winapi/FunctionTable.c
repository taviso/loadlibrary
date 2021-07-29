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

STATIC WINAPI BOOLEAN RtlAddFunctionTable(PVOID FunctionTable,
                                          DWORD EntryCount,
                                          DWORD64 BaseAddress) {
    DebugLog("%p %hhx %p", FunctionTable, EntryCount, BaseAddress);
    return true;
}

STATIC WINAPI BOOLEAN RtlDeleteFunctionTable(PVOID FunctionTable) {
    DebugLog("%p", FunctionTable);
    return true;
}

DECLARE_CRT_EXPORT("RtlAddFunctionTable", RtlAddFunctionTable);

DECLARE_CRT_EXPORT("RtlDeleteFunctionTable", RtlDeleteFunctionTable);
