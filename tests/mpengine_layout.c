#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "scanreply.h"
#include "streambuffer.h"

_Static_assert(sizeof(((struct pe_image *) 0)->size) == sizeof(size_t),
               "PE image size must match pe_load_library's output type");

/* mpengine consumes these packed structures across the DLL boundary. */
#if defined(__i386__)
_Static_assert(sizeof(SCANSTRUCT) == 116, "x86 SCANSTRUCT size");
_Static_assert(offsetof(SCANSTRUCT, FileSize) == 80, "x86 FileSize offset");
_Static_assert(offsetof(SCANSTRUCT, StreamName1) == 100, "x86 StreamName1 offset");
_Static_assert(offsetof(SCANSTRUCT, ThreatId) == 112, "x86 ThreatId offset");
_Static_assert(sizeof(SCAN_REPLY) == 16, "x86 SCAN_REPLY size");
_Static_assert(offsetof(SCAN_REPLY, field_C) == 12, "x86 SCAN_REPLY field_C offset");
_Static_assert(sizeof(SCANSTREAM_PARAMS) == 16, "x86 SCANSTREAM_PARAMS size");
_Static_assert(offsetof(SCANSTREAM_PARAMS, UnknownC) == 12, "x86 UnknownC offset");
#elif defined(__x86_64__)
_Static_assert(sizeof(SCANSTRUCT) == 136, "x64 SCANSTRUCT size");
_Static_assert(offsetof(SCANSTRUCT, FileSize) == 80, "x64 FileSize offset");
_Static_assert(offsetof(SCANSTRUCT, StreamName1) == 112, "x64 StreamName1 offset");
_Static_assert(offsetof(SCANSTRUCT, ThreatId) == 132, "x64 ThreatId offset");
_Static_assert(sizeof(SCAN_REPLY) == 24, "x64 SCAN_REPLY size");
_Static_assert(offsetof(SCAN_REPLY, field_C) == 20, "x64 SCAN_REPLY field_C offset");
_Static_assert(sizeof(SCANSTREAM_PARAMS) == 32, "x64 SCANSTREAM_PARAMS size");
_Static_assert(offsetof(SCANSTREAM_PARAMS, UnknownC) == 24, "x64 UnknownC offset");
#endif

int main(void)
{
    return 0;
}
