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
#include <sys/mman.h>
#include <errno.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "file_mapping.h"


MappedFileObjectList *FileMappingList = NULL;


STATIC HANDLE WINAPI CreateFileMappingW(HANDLE hFile,
                                        PVOID lpFileMappingAttributes,
                                        DWORD flProtect,
                                        DWORD dwMaximumSizeHigh,
                                        DWORD dwMaximumSizeLow,
                                        LPCWSTR lpName)
{
    union long_int64 file_size;

    char *file_name = CreateAnsiFromWide(lpName);

    DebugLog("%p, %#x, %#x, %#x, %p [%s]", hFile, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, file_name);

    if (dwMaximumSizeHigh != 0 || dwMaximumSizeLow != 0) {
        file_size.high = dwMaximumSizeHigh;
        file_size.low = dwMaximumSizeLow;
    }
    else {
        long curpos = ftell(hFile);
        fseek(hFile, 0, SEEK_END);

        file_size.value = ftell(hFile);

        fseek(hFile, curpos, SEEK_SET);
    }

    MappedFileEntry *mapped_file_object = (MappedFileEntry*) calloc(1, sizeof(MappedFileEntry));

    int fd = fileno(hFile);
    mapped_file_object->fd = fd;

    PVOID addr = mmap(NULL, file_size.value, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        DebugLog("[ERROR] failed to create file object mapping: %s", strerror(errno));
        free(mapped_file_object);
        return INVALID_HANDLE_VALUE;
    }
    mapped_file_object->start = (intptr_t) addr;
    mapped_file_object->end = (intptr_t) addr + file_size.value;
    mapped_file_object->size = file_size.value;

    if (FileMappingList == NULL) {
        FileMappingList = (MappedFileObjectList *) malloc(sizeof(MappedFileObjectList));
        FileMappingList->head = NULL;
    }

    AddMappedFile(mapped_file_object, FileMappingList);

    DebugLog("%p => %p", hFile, mapped_file_object);

    return mapped_file_object;
}

STATIC PVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject,
                                  DWORD dwDesiredAccess,
                                  DWORD dwFileOffsetHigh,
                                  DWORD dwFileOffsetLow,
                                  SIZE_T dwNumberOfBytesToMap)
{
    DebugLog("%p, %#x, %#x, %#x, %#x", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
    union long_int64 file_offset;
    file_offset.high = dwFileOffsetHigh;
    file_offset.low = dwFileOffsetLow;

    MappedFileEntry *MappedFile = (MappedFileEntry*) hFileMappingObject;

    PVOID FileView = malloc(dwNumberOfBytesToMap);
    if (dwNumberOfBytesToMap == 0) {
        dwNumberOfBytesToMap = MappedFile->size - file_offset.value;
        FileView = realloc(FileView, dwNumberOfBytesToMap);

    }
    if (FileView == NULL) {
        DebugLog("[ERROR] failed to allocate view of file: %s ", strerror(errno));
        return NULL;
    }

    memcpy(FileView, (void*)MappedFile->start + file_offset.value, dwNumberOfBytesToMap);

    return FileView;
}

DECLARE_CRT_EXPORT("CreateFileMappingW", CreateFileMappingW);
DECLARE_CRT_EXPORT("MapViewOfFile", MapViewOfFile);
