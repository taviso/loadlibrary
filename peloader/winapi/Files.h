#ifndef LOADLIBRARY_FILES_H
#define LOADLIBRARY_FILES_H

HANDLE WINAPI FindFirstFileW(PWCHAR lpFileName, PVOID lpFindFileData);

typedef struct WIN32_FILE_ATTRIBUTE_DATA {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA, *LPWIN32_FILE_ATTRIBUTE_DATA;
extern void WINAPI SetLastError(DWORD dwErrCode);

enum {
    CREATE_NEW          = 1,
    CREATE_ALWAYS       = 2,
    OPEN_EXISTING       = 3,
    OPEN_ALWAYS         = 4,
    TRUNCATE_EXISTING   = 5
};

#define ERROR_FILE_NOT_FOUND 2

#define FILE_ATTRIBUTE_NORMAL 128
#define FILE_ATTRIBUTE_DIRECTORY 16

#define INVALID_FILE_ATTRIBUTES -1;

#endif //LOADLIBRARY_FILES_H
