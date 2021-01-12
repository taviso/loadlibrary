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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "strings.h"

char *string_from_wchar(void *wcharbuf, size_t len)
{
    uint16_t *inbuf = wcharbuf;
    uint8_t *outbuf = NULL;
    void *buf;
    size_t count    = 0;

    if (wcharbuf == NULL)
        return NULL;

    buf = outbuf = malloc(len + 1);

    while (*outbuf++ = *inbuf++) {
        if (++count >= len) {
            *outbuf = '\0';
            break;
        }
    }

    return buf;
}

size_t CountWideChars(const void *wcharbuf)
{
    size_t i = 0;
    const uint16_t *p = wcharbuf;

    if (!p) return 0;

    while (*p++)
        i++;

    return i;
}
char * CreateAnsiFromWide(void *wcharbuf)
{
    return string_from_wchar(wcharbuf, CountWideChars(wcharbuf) * 2);
}
