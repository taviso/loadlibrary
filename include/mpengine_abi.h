#ifndef LOADLIBRARY_MPENGINE_ABI_H
#define LOADLIBRARY_MPENGINE_ABI_H

/* mpengine's client callbacks use the C convention on x86 and the
 * Microsoft x64 convention when called from a 64-bit Windows DLL. */
#if defined(__x86_64__)
#define MPENGINE_CALLBACK __attribute__((ms_abi))
#elif defined(__i386__)
#define MPENGINE_CALLBACK __attribute__((cdecl))
#else
#error Unsupported architecture for mpengine callbacks
#endif

#endif
