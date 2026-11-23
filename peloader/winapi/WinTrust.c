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

STATIC WINAPI BOOL CryptCATAdminAcquireContext(PVOID phCatAdmin, PVOID pgSubsystem, DWORD dwFlags) {
    DebugLog("%p, %p, %#x", phCatAdmin, pgSubsystem, dwFlags);
    return TRUE;
}

STATIC WINAPI HANDLE
CryptCATAdminEnumCatalogFromHash(HANDLE hCatAdmin, BYTE *pbHash, DWORD cbHash, DWORD dwFlags, PVOID phPrevCatInfo) {
    DebugLog("%p, %p, %u, %#x, %p", hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo);
    return NULL;
}

STATIC WINAPI BOOL CryptCATAdminCalcHashFromFileHandle(VOID) {
    DebugLog("FIXME");
    return 0;
}

STATIC WINAPI BOOL CryptCATAdminReleaseCatalogContext(VOID) {
    DebugLog("FIXME");
    return 0;
}

STATIC WINAPI BOOL CryptCATAdminReleaseContext(VOID) {
    DebugLog("FIXME");
    return 0;
}

STATIC WINAPI BOOL CryptCATCatalogInfoFromContext(VOID) {
    DebugLog("FIXME");
    return 0;
}

STATIC WINAPI BOOL WTHelperGetProvCertFromChain(VOID) {
    DebugLog("FIXME");
    return 0;
}

STATIC WINAPI BOOL WTHelperGetProvSignerFromChain(VOID) {
    DebugLog("FIXME");
    return 0;
}

STATIC WINAPI BOOL WTHelperProvDataFromStateData(VOID) {
    DebugLog("FIXME");
    return 0;
}

STATIC WINAPI BOOL WinVerifyTrust(VOID) {
    DebugLog("FIXME");
    return 0;
}

DECLARE_CRT_EXPORT("CryptCATAdminAcquireContext", CryptCATAdminAcquireContext);

DECLARE_CRT_EXPORT("CryptCATAdminCalcHashFromFileHandle", CryptCATAdminCalcHashFromFileHandle);

DECLARE_CRT_EXPORT("CryptCATAdminEnumCatalogFromHash", CryptCATAdminEnumCatalogFromHash);

DECLARE_CRT_EXPORT("CryptCATAdminReleaseCatalogContext", CryptCATAdminReleaseCatalogContext);

DECLARE_CRT_EXPORT("CryptCATAdminReleaseContext", CryptCATAdminReleaseContext);

DECLARE_CRT_EXPORT("CryptCATCatalogInfoFromContext", CryptCATCatalogInfoFromContext);

DECLARE_CRT_EXPORT("WTHelperGetProvCertFromChain", WTHelperGetProvCertFromChain);
//DECLARE_CRT_EXPORT("WTHelperGetProvSignerFromChain", WTHelperGetProvSignerFromChain);
DECLARE_CRT_EXPORT("WTHelperProvDataFromStateData", WTHelperProvDataFromStateData);

DECLARE_CRT_EXPORT("WinVerifyTrust", WinVerifyTrust);
