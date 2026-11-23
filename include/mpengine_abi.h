#ifndef LOADLIBRARY_MPENGINE_ABI_H
#define LOADLIBRARY_MPENGINE_ABI_H

/* mpengine calls use the C convention on x86 and the Microsoft x64 ABI. */
#if defined(__x86_64__)
#define MPENGINE_CALL __attribute__((ms_abi))
#elif defined(__i386__)
#define MPENGINE_CALL __attribute__((cdecl))
#else
#error Unsupported architecture for mpengine calls
#endif

#endif
