#ifndef LOADLIBRARY_TLSALLOC_H
#define LOADLIBRARY_TLSALLOC_H

DWORD WINAPI TlsAlloc(void);
BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, PVOID lpTlsValue);
DWORD WINAPI TlsGetValue(DWORD dwTlsIndex);
BOOL WINAPI TlsFree(DWORD dwTlsIndex);
DWORD WINAPI FlsAlloc(PVOID lpCallback);
DWORD WINAPI FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData);
DWORD WINAPI FlsGetValue(DWORD dwFlsIndex);
BOOL WINAPI FlsFree(DWORD dwFlsIndex);

#endif //LOADLIBRARY_TLSALLOC_H
