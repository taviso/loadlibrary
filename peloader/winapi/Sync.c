#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

typedef PRTL_RUN_ONCE LPINIT_ONCE;

STATIC WINAPI BOOL InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce,
                                           DWORD dwFlags,
                                           PBOOL fPending,
                                           LPVOID *lpContext) {
    NOP_FILL();

    DebugLog("%p %hhx %p %p", lpInitOnce, dwFlags, fPending, lpContext);

    return true;
}

DECLARE_CRT_EXPORT("InitOnceBeginInitialize", InitOnceBeginInitialize);
