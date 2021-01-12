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

#define HEAP_ZERO_MEMORY 8

STATIC HANDLE WINAPI GetProcessHeap(void)
{
    return (HANDLE) 'HEAP';
}

STATIC HANDLE WINAPI HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    DebugLog("%#x, %u, %u", flOptions, dwInitialSize, dwMaximumSize);
    return (HANDLE) 'HEAP';
}

STATIC PVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    PVOID Buffer;

    // DebugLog("%p, %#x, %u", hHeap, dwFlags, dwBytes);

    if (dwFlags & HEAP_ZERO_MEMORY) {
        Buffer = calloc(dwBytes, 1);
    } else {
        Buffer = malloc(dwBytes);
    }

    return Buffer;
}

STATIC BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    // DebugLog("%p, %#x, %p", hHeap, dwFlags, lpMem);

    free(lpMem);

    return TRUE;
}

STATIC BOOL WINAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress)
{
    DebugLog("%p, %#x, %p", HeapHandle, Flags, BaseAddress);

    free(BaseAddress);

    return TRUE;
}

STATIC SIZE_T WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    return malloc_usable_size(lpMem);
}

STATIC PVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, PVOID lpMem, SIZE_T dwBytes)
{
    return realloc(lpMem, dwBytes);
}

STATIC PVOID WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes)
{
    PVOID Buffer = malloc(uBytes);
    assert(uFlags == 0);

    DebugLog("%#x, %u => %p", uFlags, uBytes, Buffer);

    return Buffer;
}

STATIC PVOID WINAPI LocalFree(PVOID hMem)
{
    DebugLog("%p", hMem);
    free(hMem);
    return NULL;
}

STATIC PVOID WINAPI RtlCreateHeap(ULONG Flags,
                                  PVOID HeapBase,
                                  SIZE_T ReserveSize,
                                  SIZE_T CommitSize,
                                  PVOID Lock,
                                  PVOID Parameters)
{
    DebugLog("%#x, %p, %#x, %#x, %p, %p",
             Flags,
             HeapBase,
             ReserveSize,
             CommitSize,
             Lock,
             Parameters);

    return (HANDLE) 'HEAP';
}

STATIC PVOID WINAPI RtlAllocateHeap(PVOID HeapHandle,
                                    ULONG Flags,
                                    SIZE_T Size)
{
    DebugLog("%p, %#x, %u", HeapHandle, Flags, Size);

    return malloc(Size);
}

STATIC NTSTATUS WINAPI RtlSetHeapInformation(PVOID Heap,
                                             HEAP_INFORMATION_CLASS HeapInformationClass,
                                             PVOID HeapInformation,
                                             SIZE_T HeapInformationLength)
{
    DebugLog("%p, %d", Heap, HeapInformationLength);
    return 0;
}

STATIC PVOID WINAPI GlobalAlloc(UINT uFlags, SIZE_T uBytes)
{
    PVOID Buffer = malloc(uBytes);
    assert(uFlags == 0);

    DebugLog("%#x, %u => %p", uFlags, uBytes, Buffer);

    return Buffer;
}

STATIC PVOID WINAPI GlobalFree(PVOID hMem)
{
    DebugLog("%p", hMem);
    free(hMem);
    return NULL;
}

DECLARE_CRT_EXPORT("HeapCreate", HeapCreate);
DECLARE_CRT_EXPORT("GetProcessHeap", GetProcessHeap);
DECLARE_CRT_EXPORT("HeapAlloc", HeapAlloc);
DECLARE_CRT_EXPORT("HeapFree", HeapFree);
DECLARE_CRT_EXPORT("RtlFreeHeap", RtlFreeHeap);
DECLARE_CRT_EXPORT("RtlSetHeapInformation", RtlSetHeapInformation);
DECLARE_CRT_EXPORT("HeapSize", HeapSize);
DECLARE_CRT_EXPORT("HeapReAlloc", HeapReAlloc);
DECLARE_CRT_EXPORT("LocalAlloc", LocalAlloc);
DECLARE_CRT_EXPORT("LocalFree", LocalFree);
DECLARE_CRT_EXPORT("RtlCreateHeap", RtlCreateHeap);
DECLARE_CRT_EXPORT("RtlAllocateHeap", RtlAllocateHeap);
DECLARE_CRT_EXPORT("GlobalAlloc", GlobalAlloc);
DECLARE_CRT_EXPORT("GlobalFree", GlobalFree);
