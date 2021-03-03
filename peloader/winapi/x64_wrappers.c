#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "Heap.h"

PVOID WINAPI HeapAlloc_x64(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    __asm__("push %rsi\n"
            "push %rdi");
    DebugLog("HeapAlloc x64 wrapper");
    PVOID memBlock = HeapAlloc(hHeap, dwFlags, dwBytes);
    __asm__("pop %rdi\n"
            "pop %rsi");
    return memBlock;
}

BOOL WINAPI HeapFree_x64(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    __asm__("push %rsi\n"
            "push %rdi");
    DebugLog("HeapAlloc x64 wrapper");
    BOOL result = HeapFree(hHeap, dwFlags, lpMem);
    __asm__("pop %rdi\n"
            "pop %rsi");
    return result;
}

DECLARE_CRT_EXPORT("HeapAlloc_x64", HeapAlloc_x64);
DECLARE_CRT_EXPORT("HeapFree_x64", HeapFree_x64);
