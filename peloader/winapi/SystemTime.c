#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "winnt_types.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

typedef struct _SYSTEMTIME {
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME;

extern void WINAPI SetLastErrorLocal(DWORD dwErrCode);

// These routines are called to check if signing certificates have expired, so
// should return similar values.

STATIC VOID WINAPI GetSystemTime(PSYSTEMTIME lpSystemTime)
{
    NOP_FILL();
    memset(lpSystemTime, 0, sizeof(SYSTEMTIME));
    return;
}

STATIC BOOL WINAPI SystemTimeToFileTime(SYSTEMTIME *lpSystemTime, PFILETIME lpFileTime)
{
    NOP_FILL();
    memset(lpFileTime, 0, sizeof(FILETIME));
    return TRUE;
}

STATIC VOID WINAPI GetSystemTimePreciseAsFileTime(PFILETIME lpSystemTimeAsFileTime)
{
    NOP_FILL();
    memset(lpSystemTimeAsFileTime, 0, sizeof(FILETIME));
    return;
}

STATIC VOID WINAPI GetSystemTimeAsFileTime(PVOID lpSystemTimeAsFileTime)
{
    NOP_FILL();
    memset(lpSystemTimeAsFileTime, 0, sizeof(FILETIME));
    return;
}

STATIC BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
    NOP_FILL();
    struct timespec tm;
    DebugLog("");

    SetLastErrorLocal(0);

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &tm) != 0)
        return FALSE;

    *lpPerformanceCount = tm.tv_nsec;

    return TRUE;
}

STATIC DWORD WINAPI GetTickCount(VOID)
{
    NOP_FILL();
    return 0;
}

STATIC ULONGLONG WINAPI GetTickCount64(VOID)
{
    NOP_FILL();
    return 0;
}

STATIC BOOL WINAPI QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
    NOP_FILL();
    struct timespec tm;

    DebugLog("");

    if (clock_getres(CLOCK_MONOTONIC_RAW, &tm) != 0)
        return FALSE;

    *lpFrequency = tm.tv_nsec;

    SetLastErrorLocal(0);

    return TRUE;
}

STATIC BOOL WINAPI GetProcessTimes(HANDLE hProcess, PFILETIME lpCreationTime, PFILETIME lpExitTime, PFILETIME lpKernelTime, PFILETIME lpUserTime)
{
    NOP_FILL();
    SetLastErrorLocal(0);
    DebugLog("");
    return FALSE;
}

STATIC BOOL WINAPI DosDateTimeToFileTime(WORD wFatDate, WORD wFatTime, PFILETIME lpFileTime)
{
    NOP_FILL();
    DebugLog("");
    return FALSE;
}

STATIC BOOL WINAPI FileTimeToSystemTime(PFILETIME lpFileTime, PSYSTEMTIME lpSystemTime)
{
    NOP_FILL();
    DebugLog("");
    return FALSE;
}

DECLARE_CRT_EXPORT("GetSystemTime", GetSystemTime, 1);
DECLARE_CRT_EXPORT("SystemTimeToFileTime", SystemTimeToFileTime, 2);
DECLARE_CRT_EXPORT("GetSystemTimePreciseAsFileTime", GetSystemTimePreciseAsFileTime, 1);
DECLARE_CRT_EXPORT("GetSystemTimeAsFileTime", GetSystemTimeAsFileTime, 1);
DECLARE_CRT_EXPORT("QueryPerformanceCounter", QueryPerformanceCounter, 1);
DECLARE_CRT_EXPORT("QueryPerformanceFrequency", QueryPerformanceFrequency, 1);
DECLARE_CRT_EXPORT("GetTickCount", GetTickCount, 0);
DECLARE_CRT_EXPORT("GetTickCount64", GetTickCount64, 0);
DECLARE_CRT_EXPORT("GetProcessTimes", GetProcessTimes, 5);
DECLARE_CRT_EXPORT("DosDateTimeToFileTime", DosDateTimeToFileTime, 3);
DECLARE_CRT_EXPORT("FileTimeToSystemTime", FileTimeToSystemTime, 2);
