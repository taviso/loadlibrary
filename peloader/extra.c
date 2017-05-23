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

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"

#define MAX_EXTRA_EXPORTS 65535

struct wrap_export extra_exports[MAX_EXTRA_EXPORTS];
extern struct hsearch_data extraexports;

static void __destructor cleanup_extra_exports(void)
{
    hdestroy_r(&extraexports);
}

// This code is designed to parse a .MAP file produced by IDA.
bool process_extra_exports(void *imagebase, size_t base, const char *filename)
{
    char *name;
    uintptr_t address;
    size_t num = 0;
    FILE *exports;

    if ((exports = fopen(filename, "r")) == NULL) {
        return false;
    }

    hcreate_r(MAX_EXTRA_EXPORTS, &extraexports);

    while (!feof(exports)) {
        if (fscanf(exports, "%*X:%X %m[^\n]", &address, &name) == 2) {
            ENTRY e, *ep;
            e.key   = name;
            e.data  = (void *)((uintptr_t)(imagebase) + address + base);
            hsearch_r(e, ENTER, &ep, &extraexports);
            if (++num >= MAX_EXTRA_EXPORTS) {
                warn("large number of extra symbols in %s, increase MAX_EXTRA_EXPORTS and rebuild", filename);
                break;
            }
        } else {
            fgetc(exports);
        }
    }

    fclose(exports);
    return true;
}
