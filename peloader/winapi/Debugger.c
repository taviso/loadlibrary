#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

static BOOL WINAPI IsDebuggerPresent()
{
    DebugLog("");
    return false;
}

DECLARE_CRT_EXPORT("IsDebuggerPresent", IsDebuggerPresent);
