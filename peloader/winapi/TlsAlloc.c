
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

#ifndef TLS_OUT_OF_INDEXES
# define TLS_OUT_OF_INDEXES 0xFFFFFFFF
#endif

// Index zero is reserved for .tls
static int TlsIndex = 1;
extern uintptr_t LocalStorage[1024];

STATIC DWORD WINAPI TlsAlloc(void)
{
    if (TlsIndex >= ARRAY_SIZE(LocalStorage) - 1) {
        DebugLog("TlsAlloc() => %#x", TlsIndex);
        return TLS_OUT_OF_INDEXES;
    }

    return TlsIndex++;
}

STATIC BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, PVOID lpTlsValue)
{
    DebugLog("TlsSetValue(%u, %p)", dwTlsIndex, lpTlsValue);

    if (dwTlsIndex < ARRAY_SIZE(LocalStorage)) {
        LocalStorage[dwTlsIndex] = (uintptr_t) (lpTlsValue);
        return TRUE;
    }

    DebugLog("dwTlsIndex higher than current maximum");
    return FALSE;
}

STATIC DWORD WINAPI TlsGetValue(DWORD dwTlsIndex)
{
    if (dwTlsIndex < ARRAY_SIZE(LocalStorage)) {
        return LocalStorage[dwTlsIndex];
    }

    return 0;
}

STATIC BOOL WINAPI TlsFree(DWORD dwTlsIndex)
{
    if (dwTlsIndex < ARRAY_SIZE(LocalStorage)) {
        LocalStorage[dwTlsIndex] = (uintptr_t) NULL;
        return TRUE;
    }

    return FALSE;
}

DECLARE_CRT_EXPORT("TlsFree", TlsFree);
DECLARE_CRT_EXPORT("TlsAlloc", TlsAlloc);
DECLARE_CRT_EXPORT("TlsSetValue", TlsSetValue);
DECLARE_CRT_EXPORT("TlsGetValue", TlsGetValue);

// These deliberately don't resolve, mpengine redirects to Tls variants.
//DECLARE_CRT_EXPORT("FlsFree", NULL);
//DECLARE_CRT_EXPORT("FlsAlloc", NULL);
//DECLARE_CRT_EXPORT("FlsSetValue", NULL);
//DECLARE_CRT_EXPORT("FlsGetValue", NULL);
