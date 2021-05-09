#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "codealloc.h"

#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READWRITE 0x40

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000

#define MEM_RELEASE 0x8000

STATIC PVOID WINAPI VirtualAlloc(PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    NOP_FILL();
    if (flAllocationType & ~(MEM_COMMIT | MEM_RESERVE)) {
        DebugLog("flAllocationType %#x not implemnted", flAllocationType);
        return NULL;
    }

    // This VirtualAlloc() always returns PAGE_EXECUTE_READWRITE memory.
    if (flProtect == PAGE_READWRITE)
        return code_malloc(dwSize);
    if (flProtect == PAGE_EXECUTE_READWRITE) {
        DebugLog("JIT PAGE_EXECUTE_READWRITE Allocation Requested");
        return code_malloc(dwSize);
    }

    DebugLog("flProtect flags %#x not implemented", flProtect);
    return NULL;
}

STATIC BOOL WINAPI VirtualProtect(PVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    NOP_FILL();
    if (flNewProtect != PAGE_READONLY) {
        DebugLog("unimplemented VirtualProtect() request, %#x", flNewProtect);
    }
    return TRUE;
}

STATIC BOOL WINAPI VirtualUnlock(PVOID lpAddress, SIZE_T dwSize)
{
    NOP_FILL();
    return TRUE;
}

STATIC BOOL WINAPI VirtualFree(PVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    NOP_FILL();
    if (dwFreeType == MEM_RELEASE)
        code_free(lpAddress);
    return TRUE;
}

DECLARE_CRT_EXPORT("VirtualAlloc", VirtualAlloc, 4);
DECLARE_CRT_EXPORT("VirtualProtect", VirtualProtect, 4);
DECLARE_CRT_EXPORT("VirtualUnlock", VirtualUnlock, 2);
DECLARE_CRT_EXPORT("VirtualFree", VirtualFree, 3);
