#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
  DWORD    dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA, *LPWIN32_FILE_ATTRIBUTE_DATA;
extern void WINAPI SetLastError(DWORD dwErrCode);

#define ERROR_FILE_NOT_FOUND 2

#define FILE_ATTRIBUTE_NORMAL 128
#define FILE_ATTRIBUTE_DIRECTORY 16

#define INVALID_FILE_ATTRIBUTES -1;

static DWORD WINAPI GetFileAttributesW(PVOID lpFileName)
{
    NOP_FILL();
    DWORD Result = FILE_ATTRIBUTE_NORMAL;
    char *filename = CreateAnsiFromWide(lpFileName);
    DebugLog("%p [%s]", lpFileName, filename);

    if (strstr(filename, "RebootActions") || strstr(filename, "RtSigs")
    ) {
        Result = INVALID_FILE_ATTRIBUTES;
        goto finish;
    }

finish:
    free(filename);
    return Result;
}

static DWORD WINAPI GetFileAttributesExW(PWCHAR lpFileName, DWORD fInfoLevelId, LPWIN32_FILE_ATTRIBUTE_DATA lpFileInformation)
{
    NOP_FILL();
    char *filename = CreateAnsiFromWide(lpFileName);
    DebugLog("%p [%s], %u, %p", lpFileName, filename, fInfoLevelId, lpFileInformation);

    assert(fInfoLevelId == 0);

    lpFileInformation->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    free(filename);
    return TRUE;
}

enum {
    CREATE_NEW          = 1,
    CREATE_ALWAYS       = 2,
    OPEN_EXISTING       = 3,
    OPEN_ALWAYS         = 4,
    TRUNCATE_EXISTING   = 5
};

static HANDLE WINAPI CreateFileA(PCHAR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    NOP_FILL();
    FILE *FileHandle;

    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p", lpFileName, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    // Translate path seperator.
    while (strchr(lpFileName, '\\'))
        *strchr(lpFileName, '\\') = '/';

    // I'm just going to tolower() everything.
    for (char *t = lpFileName; *t; t++)
        *t = tolower(*t);

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            FileHandle = fopen(lpFileName, "r");
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen("/dev/null", "w");
            break;
        // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(lpFileName, "/faketemp/")) {
                FileHandle = fopen(lpFileName, "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(lpFileName);
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", lpFileName, FileHandle);

    SetLastError(ERROR_FILE_NOT_FOUND);
    return FileHandle ? FileHandle : INVALID_HANDLE_VALUE;
}


static HANDLE WINAPI CreateFileW(PWCHAR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    NOP_FILL();
    FILE *FileHandle;
    char *filename = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p", lpFileName, filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    // Translate path seperator.
    while (strchr(filename, '\\'))
        *strchr(filename, '\\') = '/';

    // I'm just going to tolower() everything.
    for (char *t = filename; *t; t++)
        *t = tolower(*t);

    //LogMessage("%u %s", dwCreationDisposition, filename);

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            FileHandle = fopen(filename, "r");
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen("/dev/null", "w");
            break;
        // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(filename, "/faketemp/")) {
                FileHandle = fopen(filename, "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(filename);
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", filename, FileHandle);

    free(filename);

    SetLastError(ERROR_FILE_NOT_FOUND);
    return FileHandle ? FileHandle : INVALID_HANDLE_VALUE;
}

/**
 * TODO: handle 64 bit 
 */
static DWORD WINAPI SetFilePointer(HANDLE hFile, LONG liDistanceToMove,  LONG *lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    NOP_FILL();
    int result;

    DebugLog("%p, %llu, %p, %u", hFile, liDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);

    result = fseek(hFile, liDistanceToMove, dwMoveMethod);

    DWORD pos = ftell(hFile);

    if (lpDistanceToMoveHigh) {
        *lpDistanceToMoveHigh = 0;
    }

    return pos;
}


static BOOL WINAPI SetFilePointerEx(HANDLE hFile, uint64_t liDistanceToMove,  uint64_t *lpNewFilePointer, DWORD dwMoveMethod)
{
    NOP_FILL();
    int result;

    //DebugLog("%p, %llu, %p, %u", hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);

    result = fseek(hFile, liDistanceToMove, dwMoveMethod);

    // dwMoveMethod maps onto SEEK_SET/SEEK_CUR/SEEK_END perfectly.
    if (lpNewFilePointer) {
        *lpNewFilePointer = ftell(hFile);
    }

    // Windows is permissive here.
    return TRUE;
    //return result != -1; 
}

static BOOL WINAPI CloseHandle(HANDLE hObject)
{
    NOP_FILL();
    DebugLog("%p", hObject);
    if (hObject != (HANDLE) 'EVNT'
     && hObject != INVALID_HANDLE_VALUE
     && hObject != (HANDLE) 'SEMA')
        fclose(hObject);
    return TRUE;
}

static BOOL WINAPI ReadFile(HANDLE hFile, PVOID lpBuffer, DWORD nNumberOfBytesToRead, PDWORD lpNumberOfBytesRead, PVOID lpOverlapped)
{
    NOP_FILL();
    *lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, hFile);
    return TRUE;
}

static BOOL WINAPI WriteFile(HANDLE hFile, PVOID lpBuffer, DWORD nNumberOfBytesToWrite, PDWORD lpNumberOfBytesWritten, PVOID lpOverlapped)
{
    NOP_FILL();
    *lpNumberOfBytesWritten = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, hFile);
    return TRUE;
}

static BOOL WINAPI DeleteFileW(PWCHAR lpFileName)
{
    NOP_FILL();
    char *AnsiFilename = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s]", lpFileName, AnsiFilename);

    free(AnsiFilename);
    return TRUE;
}

static BOOL WINAPI GetFileSizeEx(HANDLE hFile, uint64_t *lpFileSize)
{
    NOP_FILL();
    long curpos = ftell(hFile);

    fseek(hFile, 0, SEEK_END);

    *lpFileSize = ftell(hFile);

    fseek(hFile, curpos, SEEK_SET);

    DebugLog("%p, %p => %llu", hFile, lpFileSize, *lpFileSize);


    return TRUE;
}

static HANDLE WINAPI FindFirstFileW(PWCHAR lpFileName, PVOID lpFindFileData)
{
    NOP_FILL();
    char *name = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %p", lpFileName, name, lpFindFileData);

    free(name);

    SetLastError(ERROR_FILE_NOT_FOUND);

    return INVALID_HANDLE_VALUE;
}

static DWORD WINAPI NtOpenSymbolicLinkObject(PHANDLE LinkHandle, DWORD DesiredAccess, PVOID ObjectAttributes)
{
    NOP_FILL();
    *LinkHandle = (HANDLE) 'SYMB';
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI NtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength)
{
    NOP_FILL();
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI NtClose(HANDLE Handle)
{
    NOP_FILL();
    return STATUS_SUCCESS;
}

static BOOL WINAPI DeviceIoControl(
  HANDLE       hDevice,
  DWORD        dwIoControlCode,
  PVOID       lpInBuffer,
  DWORD        nInBufferSize,
  PVOID       lpOutBuffer,
  DWORD        nOutBufferSize,
  PDWORD      lpBytesReturned,
  PVOID       lpOverlapped)
{
    NOP_FILL();
    DebugLog("");
    return FALSE;
}

static NTSTATUS  NtQueryVolumeInformationFile(
 HANDLE               FileHandle,
 PVOID                IoStatusBlock,
 PVOID                FsInformation,
 ULONG                Length,
 DWORD FsInformationClass)
{
    NOP_FILL();
    DebugLog("");
    return 1;
}

static DWORD WINAPI GetFullPathNameW(
  PWCHAR lpFileName,
  DWORD   nBufferLength,
  PWCHAR  lpBuffer,
  PWCHAR  *lpFilePart)
{
    NOP_FILL();
    DebugLog("");
    return 0;
}

static BOOL SetEndOfFile(HANDLE hFile)
{
    NOP_FILL();
    DebugLog("");
    return ftruncate(fileno(hFile), ftell(hFile)) != -1;
}

static DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, PWCHAR lptstrFilename, PDWORD lpdwHandle)
{
    NOP_FILL();
    DebugLog("%#x, %p, %p", dwFlags, lptstrFilename, lpdwHandle);
    return 0;
}

static BOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, PWCHAR lptstrFilename, DWORD dwHandle, DWORD dwLen, PVOID lpData)
{
    NOP_FILL();
    DebugLog("");
    return FALSE;
}

static BOOL WINAPI VerQueryValueW(PVOID pBlock, PWCHAR lpSubBlock, PVOID  *lplpBuffer, PDWORD puLen)
{
    NOP_FILL();
    DebugLog("");
    return FALSE;
}

static DWORD WINAPI QueryDosDevice(PVOID lpDeviceName, PVOID lpTargetPath, DWORD ucchMax)
{
    NOP_FILL();
    DebugLog("");
    return 0;
}

static BOOL WINAPI GetDiskFreeSpaceExW(PWCHAR lpDirectoryName, PVOID lpFreeBytesAvailableToCaller, PVOID lpTotalNumberOfBytes, QWORD *lpTotalNumberOfFreeBytes)
{
    NOP_FILL();
    DebugLog("%S", lpDirectoryName);
    *lpTotalNumberOfFreeBytes = 0x000000000ULL;
    return FALSE;
}

DECLARE_CRT_EXPORT("VerQueryValueW", VerQueryValueW);
DECLARE_CRT_EXPORT("GetFileVersionInfoExW", GetFileVersionInfoExW);
DECLARE_CRT_EXPORT("GetFileVersionInfoSizeExW", GetFileVersionInfoSizeExW);
DECLARE_CRT_EXPORT("GetFileAttributesW", GetFileAttributesW);
DECLARE_CRT_EXPORT("GetFileAttributesExW", GetFileAttributesExW);
DECLARE_CRT_EXPORT("CreateFileA", CreateFileA);
DECLARE_CRT_EXPORT("CreateFileW", CreateFileW);
DECLARE_CRT_EXPORT("SetFilePointer", SetFilePointer);
DECLARE_CRT_EXPORT("SetFilePointerEx", SetFilePointerEx);
DECLARE_CRT_EXPORT("CloseHandle", CloseHandle);
DECLARE_CRT_EXPORT("ReadFile", ReadFile);
DECLARE_CRT_EXPORT("WriteFile", WriteFile);
DECLARE_CRT_EXPORT("DeleteFileW", DeleteFileW);
DECLARE_CRT_EXPORT("GetFileSizeEx", GetFileSizeEx);
DECLARE_CRT_EXPORT("FindFirstFileW", FindFirstFileW);
DECLARE_CRT_EXPORT("NtOpenSymbolicLinkObject", NtOpenSymbolicLinkObject);
DECLARE_CRT_EXPORT("NtQuerySymbolicLinkObject", NtQuerySymbolicLinkObject);
DECLARE_CRT_EXPORT("NtClose", NtClose);
DECLARE_CRT_EXPORT("DeviceIoControl", DeviceIoControl);
DECLARE_CRT_EXPORT("NtQueryVolumeInformationFile", NtQueryVolumeInformationFile);
DECLARE_CRT_EXPORT("GetFullPathNameW", GetFullPathNameW);
DECLARE_CRT_EXPORT("SetEndOfFile", SetEndOfFile);
DECLARE_CRT_EXPORT("QueryDosDeviceW", QueryDosDevice);
DECLARE_CRT_EXPORT("GetDiskFreeSpaceExW", GetDiskFreeSpaceExW);
