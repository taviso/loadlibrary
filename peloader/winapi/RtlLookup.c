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
#include "mpclient.h"

STATIC WINAPI PVOID RtlPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage) {
    NOP_FILL();

    PVOID ImageBase = NULL;

    DebugLog("%p %p", PcValue, BaseOfImage);

    if ((ULONG_PTR) PcValue >= (ULONG_PTR) image.image &&
            (ULONG_PTR) PcValue < (ULONG_PTR) image.image + image.size) {
        ImageBase = image.image;
    }
    else {
        DebugLog("NOT SUPPORTED");
        return NULL;
    }

    *BaseOfImage = image.image;

    return ImageBase;
}

DECLARE_CRT_EXPORT("RtlPcToFileHeader", RtlPcToFileHeader, 2);
