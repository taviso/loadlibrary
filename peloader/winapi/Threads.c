#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

static __stdcall PVOID CreateThreadPoolWait(PVOID pwa)
{
    DebugLog("");
    return (PVOID) 0x41414141;
}

static __stdcall PVOID CreateThreadPool(PVOID reserved)
{
    DebugLog("");
    return (PVOID) 0x41414141;
}

static __stdcall PVOID CreateThreadpoolTimer(PVOID pfnti, PVOID pv, PVOID pcbe)
{
    DebugLog("");
    return (PVOID) 0x41414141;
}

static __stdcall PVOID CreateThreadpoolWork(PVOID pfnwk, PVOID pv, PVOID pcbe)
{
    DebugLog("");
    return (PVOID) 0x41414141;
}

static __stdcall void CloseThreadpoolTimer(PVOID pti)
{
    DebugLog("%p", pti);
}

static __stdcall void InitializeConditionVariable(PVOID ConditionVariable)
{
    DebugLog("%p", ConditionVariable);
}

static __stdcall BOOL SleepConditionVariableCS(PVOID ConditionVariable,
                                               PVOID CriticalSection,
                                               DWORD dwMilliseconds)
{
    DebugLog("%p %p %u", ConditionVariable, CriticalSection, dwMilliseconds);
    return TRUE;
}

static __stdcall void WakeAllConditionVariable(PVOID ConditionVariable)
{
    DebugLog("%p", ConditionVariable);
}


static __stdcall PVOID CreateThreadpoolWait() { DebugLog(""); return NULL; }
static __stdcall PVOID SetThreadpoolWait() { DebugLog(""); return NULL; }
static __stdcall PVOID SubmitThreadpoolWork() { DebugLog(""); return NULL; }
static __stdcall PVOID CancelThreadpoolIo() { DebugLog(""); return NULL; }
static __stdcall PVOID CloseThreadpool() { DebugLog(""); return NULL; }
static __stdcall PVOID CloseThreadpoolIo() { DebugLog(""); return NULL; }
static __stdcall PVOID CloseThreadpoolWait() { DebugLog(""); return NULL; }
static __stdcall void CloseThreadpoolWork(PVOID pwk)
{
    DebugLog("%p", pwk);
}
static __stdcall PVOID CreateThreadpool() { DebugLog(""); return NULL; }
static __stdcall PVOID CreateThreadpoolIo() { DebugLog(""); return NULL; }
static __stdcall PVOID SetThreadpoolThreadMaximum() { DebugLog(""); return NULL; }
static __stdcall PVOID SetThreadpoolThreadMinimum() { DebugLog(""); return NULL; }
static __stdcall PVOID StartThreadpoolIo() { DebugLog(""); return NULL; }
static __stdcall PVOID WaitForThreadpoolIoCallbacks() { DebugLog(""); return NULL; }
static __stdcall PVOID WaitForThreadpoolWaitCallbacks() { DebugLog(""); return NULL; }

static __stdcall void WaitForThreadpoolWorkCallbacks(PVOID pwk, BOOL fCancelPendingCallbacks)
{
    DebugLog("%p %d", pwk, fCancelPendingCallbacks);
}


DECLARE_CRT_EXPORT("CreateThreadPoolWait", CreateThreadPoolWait);
DECLARE_CRT_EXPORT("CreateThreadPool", CreateThreadPool);
DECLARE_CRT_EXPORT("InitializeConditionVariable", InitializeConditionVariable);
DECLARE_CRT_EXPORT("SleepConditionVariableCS", SleepConditionVariableCS);
DECLARE_CRT_EXPORT("WakeAllConditionVariable", WakeAllConditionVariable);

DECLARE_CRT_EXPORT("CreateThreadpoolTimer", CreateThreadpoolTimer);
DECLARE_CRT_EXPORT("CloseThreadpoolTimer", CloseThreadpoolTimer);
DECLARE_CRT_EXPORT("CreateThreadpoolWait", CreateThreadpoolWait);
DECLARE_CRT_EXPORT("SetThreadpoolWait", SetThreadpoolWait);
DECLARE_CRT_EXPORT("CloseThreadpoolWait", CloseThreadpoolWait);
DECLARE_CRT_EXPORT("CreateThreadpoolWork", CreateThreadpoolWork);
DECLARE_CRT_EXPORT("SubmitThreadpoolWork", SubmitThreadpoolWork);
DECLARE_CRT_EXPORT("CancelThreadpoolIo", CancelThreadpoolIo);
DECLARE_CRT_EXPORT("CloseThreadpool", CloseThreadpool);
DECLARE_CRT_EXPORT("CloseThreadpoolIo", CloseThreadpoolIo);
DECLARE_CRT_EXPORT("CloseThreadpoolWork", CloseThreadpoolWork);
DECLARE_CRT_EXPORT("CreateThreadpool", CreateThreadpool);
DECLARE_CRT_EXPORT("CreateThreadpoolIo", CreateThreadpoolIo);
DECLARE_CRT_EXPORT("SetThreadpoolThreadMaximum", SetThreadpoolThreadMaximum);
DECLARE_CRT_EXPORT("SetThreadpoolThreadMinimum", SetThreadpoolThreadMinimum);
DECLARE_CRT_EXPORT("StartThreadpoolIo", StartThreadpoolIo);
DECLARE_CRT_EXPORT("WaitForThreadpoolIoCallbacks", WaitForThreadpoolIoCallbacks);
DECLARE_CRT_EXPORT("WaitForThreadpoolWaitCallbacks", WaitForThreadpoolWaitCallbacks);
DECLARE_CRT_EXPORT("WaitForThreadpoolWorkCallbacks", WaitForThreadpoolWorkCallbacks);
