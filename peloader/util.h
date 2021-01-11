#ifndef __UTIL_H
#define __UTIL_H
#pragma once

bool IsGdbPresent();

#ifdef __linux__
#define __thiscall      __attribute__((thiscall))
#define __fastcall      __attribute__((fastcall))
#define __stdcall       __attribute__((stdcall))
#define __packed        __attribute__((packed))
#define __detour
#define __constructor   __attribute__((constructor))
#define __destructor    __attribute__((destructor))
#define __debugbreak()  __asm__("int3")
#define __cdecl         __attribute__((cdecl))
#define __export        __attribute__ ((externally_visible))
#define __noinline      __attribute__ ((noinline))
#else
#define __noinline
#endif

#define MIN(x, y)       ((x) > (y) ? (y) : (x))

static inline void *ZeroMemory(void *s, size_t n)
{
    return memset(s, 0, n);
}

#else
# warning util.h included twice
#endif
