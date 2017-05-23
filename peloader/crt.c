//
// Copyright (C) 2017 Tavis Ormandy
//
// Portions of this code are based on ndiswrapper, which included this
// notice:
//
// Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#define VA_LIST_DECL(_args)
#define VA_LIST_PREP(_args)
#define VA_LIST_CONV(_args) (_args)
#define VA_LIST_FREE(_args)
#define FMT_DECL(_fmt)
#define FMT_PREP(_fmt)
#define FMT_CONV(_fmt) (format)
#define FMT_FREE(_fmt)


#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "crt_exports.h"

#define EXIT2(stmt) do { stmt; } while (0)
#define TRACE2(a,b,...)
#define TODO(...)
#define ERROR(...)

__attribute__((format(printf, 2, 3)))
noregparm INT WIN_FUNC(_win_sprintf,12)
        (char *buf, const char *format, ...)
{
        va_list args;
        int res;
        FMT_DECL(format)

        FMT_PREP(format);
        va_start(args, format);
        res = vsprintf(buf, FMT_CONV(format), args);
        va_end(args);
        FMT_FREE(format);

        TRACE2("buf: %p: %s", buf, buf);
        return res;
}

noregparm INT WIN_FUNC(swprintf,12)
        (wchar_t *buf, const wchar_t *format, ...)
{
        TODO();
        EXIT2(return 0);
}

noregparm INT WIN_FUNC(_win_vsprintf,3)
        (char *str, const char *format, va_list ap)
{
        INT i;
        VA_LIST_DECL(ap)
        FMT_DECL(format)

        VA_LIST_PREP(ap);
        FMT_PREP(format);

        i = vsprintf(str, FMT_CONV(format), VA_LIST_CONV(ap));
        TRACE2("str: %p: %s", str, str);

        FMT_FREE(format);
        VA_LIST_FREE(ap);
        EXIT2(return i);
}

__attribute__((format(printf, 3, 4)))
noregparm INT WIN_FUNC(_win_snprintf,12)
        (char *buf, SIZE_T count, const char *format, ...)
{
        va_list args;
        int res;
        FMT_DECL(format)

        FMT_PREP(format);
        va_start(args, format);
        res = vsnprintf(buf, count, FMT_CONV(format), args);
        va_end(args);
        TRACE2("buf: %p: %s", buf, buf);

        FMT_FREE(format);
        return res;
}

__attribute__((format(printf, 3, 4)))
noregparm INT WIN_FUNC(_win__snprintf,12)
        (char *buf, SIZE_T count, const char *format, ...)
{
        va_list args;
        int res;
        FMT_DECL(format)

        FMT_PREP(format);
        va_start(args, format);
        res = vsnprintf(buf, count, FMT_CONV(format), args);
        va_end(args);
        TRACE2("buf: %p: %s", buf, buf);

        FMT_FREE(format);
        return res;
}

noregparm INT WIN_FUNC(_win_vsnprintf,4)
        (char *str, SIZE_T size, const char *format, va_list ap)
{
        INT i;
        VA_LIST_DECL(ap)
        FMT_DECL(format)

        VA_LIST_PREP(ap);
        FMT_PREP(format);

        i = vsnprintf(str, size, FMT_CONV(format), VA_LIST_CONV(ap));
        TRACE2("str: %p: %s", str, str);

        FMT_FREE(format);
        VA_LIST_FREE(ap);
        EXIT2(return i);
}

noregparm INT WIN_FUNC(_win__vsnprintf,4)
        (char *str, SIZE_T size, const char *format, va_list ap)
{
        INT i;
        VA_LIST_DECL(ap)
        FMT_DECL(format)

        VA_LIST_PREP(ap);
        FMT_PREP(format);

        i = vsnprintf(str, size, FMT_CONV(format), VA_LIST_CONV(ap));
        TRACE2("str: %p: %s", str, str);

        FMT_FREE(format);
        VA_LIST_FREE(ap);
        EXIT2(return i);
}

noregparm INT WIN_FUNC(_win__vsnwprintf,4)
        (wchar_t *str, SIZE_T size, const wchar_t *format, va_list ap)
{
        int ret;

        TODO();         /* format expansion not implemented */

        _win_wcsncpy(str, format, size);

        ret = _win_wcslen(str);

        if (ret >= size)
                ret = -1;
        return ret;
}

noregparm char *WIN_FUNC(_win_strncpy,3)
        (char *dst, char *src, SIZE_T n)
{
        return strncpy(dst, src, n);
}

noregparm SIZE_T WIN_FUNC(_win_strlen,1)
        (const char *s)
{
        return strlen(s);
}

noregparm INT WIN_FUNC(_win_strncmp,3)
        (const char *s1, const char *s2, SIZE_T n)
{
        return strncmp(s1, s2, n);
}

noregparm INT WIN_FUNC(_win_strcmp,2)
        (const char *s1, const char *s2)
{
        return strcmp(s1, s2);
}

noregparm INT WIN_FUNC(_win_stricmp,2)
        (const char *s1, const char *s2)
{
        return strcasecmp(s1, s2);
}

noregparm INT WIN_FUNC(_win_strnicmp,3)
        (const char *s1, const char *s2, size_t n)
{
        return strncasecmp(s1, s2, n);
}

noregparm char *WIN_FUNC(_win_strncat,3)
        (char *dest, const char *src, SIZE_T n)
{
        return strncat(dest, src, n);
}

noregparm INT WIN_FUNC(_win_wcscmp,2)
        (const wchar_t *s1, const wchar_t *s2)
{
        while (*s1 && *s1 == *s2) {
                s1++;
                s2++;
        }
        return *s1 - *s2;
}

noregparm INT WIN_FUNC(_win_wcsicmp,2)
        (const wchar_t *s1, const wchar_t *s2)
{
        while (*s1 && tolower((char)*s1) == tolower((char)*s2)) {
                s1++;
                s2++;
        }
        return tolower((char)*s1) - tolower((char)*s2);
}

noregparm SIZE_T WIN_FUNC(_win_wcslen,1)
        (const wchar_t *s)
{
        const wchar_t *t = s;
        while (*t)
                t++;
        return t - s;
}

noregparm wchar_t *WIN_FUNC(_win_wcsncpy,3)
        (wchar_t *dest, const wchar_t *src, SIZE_T n)
{
        const wchar_t *s;
        wchar_t *d;
        s = src + n;
        d = dest;
        while (src < s && (*d++ = *src++))
                ;
        if (s > src)
                memset(d, 0, (s - src) * sizeof(wchar_t));
        return dest;
}

noregparm wchar_t *WIN_FUNC(_win_wcscpy,2)
        (wchar_t *dest, const wchar_t *src)
{
        wchar_t *d = dest;
        while ((*d++ = *src++))
                ;
        return dest;
}

noregparm wchar_t *WIN_FUNC(_win_wcscat,2)
        (wchar_t *dest, const wchar_t *src)
{
        wchar_t *d;
        d = dest;
        while (*d)
                d++;
        while ((*d++ = *src++))
                ;
        return dest;
}

noregparm INT WIN_FUNC(_win_towupper,1)
        (wchar_t c)
{
        return toupper(c);
}

noregparm INT WIN_FUNC(_win_towlower,1)
        (wchar_t c)
{
        return tolower(c);
}

noregparm INT WIN_FUNC(_win_tolower,1)
        (INT c)
{
        return tolower(c);
}

noregparm INT WIN_FUNC(_win_toupper,1)
        (INT c)
{
        return toupper(c);
}

noregparm void *WIN_FUNC(_win_strcpy,2)
        (void *to, const void *from)
{
        return strcpy(to, from);
}

noregparm char *WIN_FUNC(_win_strstr,2)
        (const char *s1, const char *s2)
{
        return strstr(s1, s2);
}

noregparm char *WIN_FUNC(_win_strchr,2)
        (const char *s, int c)
{
        return strchr(s, c);
}

noregparm char *WIN_FUNC(_win_strrchr,2)
        (const char *s, int c)
{
        return strrchr(s, c);
}

noregparm void *WIN_FUNC(_win_memmove,3)
        (void *to, void *from, SIZE_T count)
{
        return memmove(to, from, count);
}

noregparm void *WIN_FUNC(_win_memchr,3)
        (const void *s, INT c, SIZE_T n)
{
        return memchr(s, c, n);
}

noregparm void *WIN_FUNC(_win_memcpy,3)
        (void *to, const void *from, SIZE_T n)
{
        return memcpy(to, from, n);
}

noregparm void *WIN_FUNC(_win_memset,3)
        (void *s, char c, SIZE_T count)
{
        return memset(s, c, count);
}

noregparm int WIN_FUNC(_win_memcmp,3)
        (void *s1, void *s2, SIZE_T n)
{
        return memcmp(s1, s2, n);
}

noregparm int WIN_FUNC(_win_atoi,1)
        (const char *ptr)
{
        int i = strtol(ptr, NULL, 10);
        return i;
}

noregparm int WIN_FUNC(_win_isdigit,1)
        (int c)
{
        return isdigit(c);
}
noregparm int WIN_FUNC(_win_isxdigit,1)
        (int c)
{
        return isxdigit(c);
}

noregparm int WIN_FUNC(_win_isalpha,1)
        (int c)
{
        return isalpha(c);
}

noregparm int WIN_FUNC(_win_isalnum,1)
        (int c)
{
        return isalnum(c);
}

noregparm int WIN_FUNC(_win_islower,1)
        (int c)
{
        return islower(c);
}

noregparm int WIN_FUNC(_win_isspace,1)
        (int c)
{
        return isspace(c);
}

noregparm int WIN_FUNC(_win_isprint,1)
        (int c)
{
        return isprint(c);
}

wstdcall int64_t WIN_FUNC(_alldiv,2)
        (int64_t a, int64_t b)
{
        return a / b;
}

wstdcall uint64_t WIN_FUNC(_aulldiv,2)
        (uint64_t a, uint64_t b)
{
        return a / b;
}

wstdcall int64_t WIN_FUNC(_allmul,2)
        (int64_t a, int64_t b)
{
        return a * b;
}

wstdcall uint64_t WIN_FUNC(_aullmul,2)
        (uint64_t a, uint64_t b)
{
        return a * b;
}

wstdcall int64_t WIN_FUNC(_allrem,2)
        (int64_t a, int64_t b)
{
        return a % b;
}

wstdcall uint64_t WIN_FUNC(_aullrem,2)
        (uint64_t a, uint64_t b)
{
        return a % b;
}

regparm3 int64_t WIN_FUNC(_allshl,2)
        (int64_t a, uint8_t b)
{
        return a << b;
}

regparm3 uint64_t WIN_FUNC(_aullshl,2)
        (uint64_t a, uint8_t b)
{
        return a << b;
}

regparm3 int64_t WIN_FUNC(_allshr,2)
        (int64_t a, uint8_t b)
{
        return a >> b;
}

regparm3 uint64_t WIN_FUNC(_aullshr,2)
        (uint64_t a, uint8_t b)
{
        return a >> b;
}
