#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <string.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

HRESULT WINAPI WerRegisterMemoryBlock(PVOID pvAddress,
                                      DWORD dwSize)
{
    DebugLog("%p, %d", pvAddress, dwSize);
    return 0;
}

DECLARE_CRT_EXPORT("WerRegisterMemoryBlock", WerRegisterMemoryBlock);
