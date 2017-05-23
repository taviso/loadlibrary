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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>

#include "log.h"

void l_message_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s(): ", function);
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    return;
}

void l_warning_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s(): ", function);

    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);

    fputc('\n', stderr);

    return;
}

void l_error_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s(): ", function);
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    return;
}

void l_debug_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s(): ", function);
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    return;
}
