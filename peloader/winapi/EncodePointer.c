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


STATIC PVOID WINAPI EncodePointer(PVOID Ptr)
{
    NOP_FILL();
    DebugLog("%p", Ptr);

    // Super secret high-security encryption algorithm.
    return (PVOID)((uintptr_t)(Ptr) ^ ~0);
}

STATIC PVOID WINAPI DecodePointer(PVOID Ptr)
{
    NOP_FILL();
    DebugLog("%p", Ptr);

    return (PVOID)((uintptr_t)(Ptr) ^ ~0);
}


DECLARE_CRT_EXPORT("EncodePointer", EncodePointer);
DECLARE_CRT_EXPORT("DecodePointer", DecodePointer);
