#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define STD_INPUT_HANDLE -10
#define STD_OUTPUT_HANDLE -11
#define STD_ERROR_HANDLE -12

#define FILE_TYPE_CHAR 0x0002
#define FILE_TYPE_DISK 0x0001
#define FILE_TYPE_PIPE 0x0003
#define FILE_TYPE_REMOTE 0x8000
#define FILE_TYPE_UNKNOWN 0x0000

STATIC HANDLE WINAPI GetStdHandle(DWORD nStdHandle)
{
    DebugLog("%d", nStdHandle);

    switch (nStdHandle) {
        case STD_INPUT_HANDLE:
            return (HANDLE) 0;
        case STD_OUTPUT_HANDLE:
            return (HANDLE) 1;
        case STD_ERROR_HANDLE:
            return (HANDLE) 2;
    }

    return INVALID_HANDLE_VALUE;
}

STATIC DWORD WINAPI GetFileType(HANDLE hFile)
{
    DebugLog("%p", hFile);

    return FILE_TYPE_CHAR;
}

DECLARE_CRT_EXPORT("GetStdHandle", GetStdHandle);
DECLARE_CRT_EXPORT("GetFileType", GetFileType);
