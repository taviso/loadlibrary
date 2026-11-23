#ifndef LOADLIBRARY_WINAPI_ABI_H
#define LOADLIBRARY_WINAPI_ABI_H

/* Windows calls use the Microsoft x64 ABI, or stdcall on 32-bit x86. */
#if defined(__x86_64__)
#define WINAPI __attribute__((ms_abi))
#define wstdcall WINAPI
#elif defined(__i386__)
#define WINAPI __attribute__((__stdcall__))
/* Some loader types explicitly require stack-passed arguments even when
 * the compiler is configured with a nonzero default regparm value. */
#define wstdcall WINAPI __attribute__((regparm(0)))
#else
#error Unsupported architecture for Windows calls
#endif

#endif
