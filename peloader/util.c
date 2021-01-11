//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"

// Quick check if I'm running under GDB.
bool IsGdbPresent()
{
    char *statusline;
    FILE *status;
    size_t len;
    bool result;

    if (getenv("NO_DEBUGGER_PRESENT")) {
        return false;
    }

    statusline = NULL;
    status     = NULL;
    len        = 0;
    result     = true;

    if ((status = fopen("/proc/self/status", "r")) == NULL) {
        LogMessage("failed to open status file, cannot determine debug status");
        return false;
    }

    while (getline(&statusline, &len, status) != -1) {
        if (strcmp(statusline, "TracerPid:\t0\n") == 0) {
            result = false;
            break;
        }
    }

    free(statusline);
    fclose(status);

    return result;
}

