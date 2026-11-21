#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <unistd.h>
#include <setjmp.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

static PVOID WINAPI CreateThreadpoolTimer(PVOID pfnti, PVOID pv, PVOID pcbe) {
    // DebugLog("%p, %p, %p", pfnti, pv, pcbe);
    return (PVOID) 'POOL';
}

static VOID WINAPI InitializeSRWLock(PVOID SRWLock) {
    DebugLog("%p", SRWLock);
}

static VOID WINAPI SetThreadpoolTimer(PVOID pti, PVOID pftDueTime, DWORD msPeriod, DWORD msWindowLength) {
    DebugLog("%p, %p, %u, %u", pti, pftDueTime, msPeriod, msWindowLength);
}

static VOID WINAPI WaitForThreadpoolTimerCallbacks(PVOID pti, BOOL fCancelPendingCallbacks) {
    DebugLog("%p, %u", pti, fCancelPendingCallbacks);
}

static VOID WINAPI CloseThreadpoolTimer(PVOID pti) {
    DebugLog("%p", pti);
}

static LONG WINAPI InterlockedDecrement(PULONG Addend) {
    DebugLog("%p", Addend);
    return --*Addend;
}

static LONG WINAPI InterlockedIncrement(PULONG Addend) {
    DebugLog("%p", Addend);
    return ++*Addend;
}

static LONG WINAPI InterlockedCompareExchange(PULONG Destination, LONG Exchange, LONG Comparand) {
    DebugLog("%p", Destination);
    if (*Destination == Comparand) {
        *Destination = Exchange;
    }
    return *Destination;
}

static HANDLE WINAPI
CreateSemaphoreW(PVOID lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, PWCHAR lpName) {
    char *name;
#ifndef NDEBUG
    name = CreateAnsiFromWide(lpName);
#else
    name = NULL;
#endif
    DebugLog("%p, %u, %u, %p [%s]", lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, name);
    free(name);
    return (HANDLE) 'SEMA';
}

static HANDLE WINAPI GetCurrentProcess(VOID) {
    return (HANDLE) -1;
}

static HANDLE WINAPI GetCurrentThread(VOID) {
    return (HANDLE) -1;
}

// loadlibrary is single threaded, so CreateThread() runs the new thread to
// completion synchronously before returning. This is enough for code that
// starts a worker and then waits for it (e.g. std::thread + join, or timed
// calls that wait for a result with a timeout).
typedef DWORD (WINAPI *PTHREAD_START_ROUTINE)(PVOID lpParameter);

typedef struct _SYNTHETIC_THREAD {
    PTHREAD_START_ROUTINE StartAddress;
    PVOID Parameter;
    DWORD ThreadId;
    DWORD ExitCode;
    jmp_buf ExitContext;
    struct _SYNTHETIC_THREAD *Parent;
} SYNTHETIC_THREAD, *PSYNTHETIC_THREAD;

#define CREATE_SUSPENDED    0x00000004
#define STILL_ACTIVE        259
#define WAIT_OBJECT_0       0
#define WAIT_TIMEOUT        258

extern uintptr_t LocalStorage[1024];
extern PFLS_CALLBACK_FUNCTION FlsCallbacks[1024];

static PSYNTHETIC_THREAD CurrentThread;     // Thread currently executing, NULL for main.
static PSYNTHETIC_THREAD SuspendedThread;   // Thread created with CREATE_SUSPENDED.
static DWORD LastThreadExitCode = STILL_ACTIVE;
static DWORD ThreadCount;

static void RunSyntheticThread(PSYNTHETIC_THREAD Thread)
{
    uintptr_t *ParentStorage;
#ifndef __x86_64__
    PVOID ExceptionList;
#endif

    // Every thread gets its own (initially empty) TLS slots. Slot zero is the
    // static TLS block of the image, which we have to share.
    ParentStorage = malloc(sizeof LocalStorage);
    memcpy(ParentStorage, LocalStorage, sizeof LocalStorage);
    memset(&LocalStorage[1], 0, sizeof LocalStorage - sizeof LocalStorage[0]);

    // Save the SEH chain, the thread may leave frames behind if it exits early.
#ifndef __x86_64__
    asm volatile("mov %%fs:0, %[list]" : [list] "=r"(ExceptionList));
#endif

    Thread->Parent = CurrentThread;
    CurrentThread  = Thread;

    DebugLog("thread %#x starting at %p(%p)", Thread->ThreadId, Thread->StartAddress, Thread->Parameter);

    if (setjmp(Thread->ExitContext) == 0) {
        Thread->ExitCode = Thread->StartAddress(Thread->Parameter);
    }

    DebugLog("thread %#x exited with code %#x", Thread->ThreadId, Thread->ExitCode);

    // Thread is exiting, run any FLS callbacks for slots it used.
    for (int i = 1; i < ARRAY_SIZE(LocalStorage); i++) {
        if (FlsCallbacks[i] && LocalStorage[i]) {
            ((void (WINAPI *)(PVOID)) FlsCallbacks[i])((PVOID) LocalStorage[i]);
        }
    }

    CurrentThread = Thread->Parent;

#ifndef __x86_64__
    asm volatile("mov %[list], %%fs:0" :: [list] "r"(ExceptionList));
#endif

    memcpy(LocalStorage, ParentStorage, sizeof LocalStorage);
    free(ParentStorage);

    LastThreadExitCode = Thread->ExitCode;
    free(Thread);
}

static HANDLE WINAPI CreateThread(PVOID lpThreadAttributes,
                                  SIZE_T dwStackSize,
                                  PTHREAD_START_ROUTINE lpStartAddress,
                                  PVOID lpParameter,
                                  DWORD dwCreationFlags,
                                  PDWORD lpThreadId)
{
    PSYNTHETIC_THREAD Thread = calloc(1, sizeof *Thread);

    DebugLog("%p, %#x, %p, %p, %#x, %p", lpThreadAttributes,
                                         dwStackSize,
                                         lpStartAddress,
                                         lpParameter,
                                         dwCreationFlags,
                                         lpThreadId);

    Thread->StartAddress = lpStartAddress;
    Thread->Parameter    = lpParameter;
    Thread->ThreadId     = getpid() + ++ThreadCount;

    if (lpThreadId)
        *lpThreadId = Thread->ThreadId;

    LastThreadExitCode = STILL_ACTIVE;

    if (dwCreationFlags & CREATE_SUSPENDED) {
        if (SuspendedThread) {
            DebugLog("FIXME: only one suspended thread supported");
            free(Thread);
            return NULL;
        }
        SuspendedThread = Thread;
    } else {
        RunSyntheticThread(Thread);
    }

    return (HANDLE) 'THRD';
}

static DWORD WINAPI ResumeThread(HANDLE hThread)
{
    PSYNTHETIC_THREAD Thread = SuspendedThread;

    DebugLog("%p", hThread);

    if (Thread == NULL)
        return 0;

    SuspendedThread = NULL;
    RunSyntheticThread(Thread);
    return 1;
}

static VOID WINAPI ExitThread(DWORD dwExitCode)
{
    DebugLog("%#x", dwExitCode);

    if (CurrentThread == NULL) {
        DebugLog("main thread called ExitThread(), exiting");
        exit(dwExitCode);
    }

    CurrentThread->ExitCode = dwExitCode;
    longjmp(CurrentThread->ExitContext, 1);
}

static VOID WINAPI FreeLibraryAndExitThread(HANDLE hLibModule, DWORD dwExitCode)
{
    DebugLog("%p, %#x", hLibModule, dwExitCode);
    ExitThread(dwExitCode);
}

static BOOL WINAPI GetExitCodeThread(HANDLE hThread, PDWORD lpExitCode)
{
    DebugLog("%p", hThread);
    *lpExitCode = LastThreadExitCode;
    return TRUE;
}

static DWORD WINAPI GetCurrentThreadId(VOID)
{
    if (CurrentThread)
        return CurrentThread->ThreadId;

    return getpid();
}

static DWORD WINAPI GetCurrentProcessId(VOID) {
    return getpid();
}

static BOOL WINAPI RegisterWaitForSingleObject(PHANDLE phNewWaitObject, HANDLE hObject, PVOID Callback, PVOID Context,
                                               ULONG dwMilliseconds, ULONG dwFlags) {
    DebugLog("");
    return TRUE;
}

static VOID WINAPI AcquireSRWLockExclusive(PVOID SRWLock) {
    DebugLog("%p", SRWLock);
}

static VOID WINAPI AcquireSRWLockShared(PVOID SRWLock) {
    DebugLog("%p", SRWLock);
}

static VOID WINAPI ReleaseSRWLockExclusive(PVOID SRWLock) {
    DebugLog("%p", SRWLock);
}

static VOID WINAPI ReleaseSRWLockShared(PVOID SRWLock) {
    DebugLog("%p", SRWLock);
}

static HANDLE WINAPI CreateMutexW(PVOID lpMutexAttributes, BOOL bInitialOwner, PWCHAR lpName) {
    DebugLog("%p, %u, %p");
    return INVALID_HANDLE_VALUE;
}

static DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    DebugLog("%p, %u", hHandle, dwMilliseconds);

    // Threads always run to completion in CreateThread().
    if (hHandle == (HANDLE) 'THRD')
        return WAIT_OBJECT_0;

    return -1;
}

static DWORD WINAPI WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable)
{
    return WaitForSingleObject(hHandle, dwMilliseconds);
}

static ULONG WINAPI LsaNtStatusToWinError(NTSTATUS Status)
{
    DebugLog("%#x", Status);
    return Status;
}

static BOOL WINAPI CreateTimerQueueTimer(PHANDLE phNewTimer,
                                         HANDLE TimerQueue,
                                         PVOID Callback,
                                         PVOID Parameter,
                                         DWORD DueTime,
                                         DWORD Period,
                                         ULONG Flags) {
    DebugLog("");
    return TRUE;
}

static BOOL WINAPI GetThreadTimes(HANDLE hThread,
                                  PFILETIME lpCreationTime,
                                  PFILETIME lpExitTime,
                                  PFILETIME lpKernelTime,
                                  PFILETIME lpUserTime) {
    DebugLog("");
    return TRUE;
}

static ULONG WINAPI RtlNtStatusToDosError(NTSTATUS Status) {
    DebugLog("%#x", Status);
    return 5;
}

static BOOL WINAPI SetThreadToken(PHANDLE Thread, HANDLE Token) {
    DebugLog("");
    return FALSE;
}

static BOOL WINAPI ProcessIdToSessionId(DWORD dwProcessId, DWORD *pSessionId) {
    DebugLog("");
    return FALSE;
}

/* One-time initialization. Single-threaded here: run the callback once and
 * remember completion in the first pointer-sized word of the INIT_ONCE. */
typedef BOOL (WINAPI *PINIT_ONCE_FN)(PVOID InitOnce, PVOID Parameter, PVOID *Context);

static BOOL WINAPI InitOnceExecuteOnce(PVOID *InitOnce, PINIT_ONCE_FN InitFn, PVOID Parameter, PVOID *Context)
{
    DebugLog("%p", InitOnce);

    if (InitOnce && *InitOnce) {
        if (Context) *Context = *InitOnce;
        return TRUE;
    }

    PVOID local = NULL;
    BOOL r = InitFn ? InitFn(InitOnce, Parameter, &local) : TRUE;
    if (r) {
        if (InitOnce) *InitOnce = local ? local : (PVOID) 1;
        if (Context)  *Context  = local;
    }
    return r;
}

static BOOL WINAPI InitOnceBeginInitialize(PVOID *InitOnce, DWORD Flags, BOOL *Pending, PVOID *Context)
{
    DebugLog("%p, %#x", InitOnce, Flags);

    if (InitOnce && *InitOnce) {
        if (Pending) *Pending = FALSE;
        if (Context) *Context = *InitOnce;
        return TRUE;
    }
    if (Flags & 1 /* INIT_ONCE_CHECK_ONLY */) {
        if (Pending) *Pending = FALSE;
        return FALSE;
    }
    if (Pending) *Pending = TRUE;
    return TRUE;
}

static BOOL WINAPI InitOnceComplete(PVOID *InitOnce, DWORD Flags, PVOID Context)
{
    DebugLog("%p, %#x", InitOnce, Flags);
    if (InitOnce) *InitOnce = Context ? Context : (PVOID) 1;
    return TRUE;
}

DECLARE_CRT_EXPORT("InitOnceExecuteOnce", InitOnceExecuteOnce);
DECLARE_CRT_EXPORT("InitOnceBeginInitialize", InitOnceBeginInitialize);
DECLARE_CRT_EXPORT("InitOnceComplete", InitOnceComplete);
DECLARE_CRT_EXPORT("RtlNtStatusToDosError", RtlNtStatusToDosError);

DECLARE_CRT_EXPORT("GetThreadTimes", GetThreadTimes);

DECLARE_CRT_EXPORT("GetCurrentThread", GetCurrentThread);

DECLARE_CRT_EXPORT("CreateTimerQueueTimer", CreateTimerQueueTimer);

DECLARE_CRT_EXPORT("RegisterWaitForSingleObject", RegisterWaitForSingleObject);

DECLARE_CRT_EXPORT("WaitForSingleObject", WaitForSingleObject);
DECLARE_CRT_EXPORT("WaitForSingleObjectEx", WaitForSingleObjectEx);
DECLARE_CRT_EXPORT("CreateThread", CreateThread);
DECLARE_CRT_EXPORT("ResumeThread", ResumeThread);
DECLARE_CRT_EXPORT("ExitThread", ExitThread);
DECLARE_CRT_EXPORT("FreeLibraryAndExitThread", FreeLibraryAndExitThread);
DECLARE_CRT_EXPORT("GetExitCodeThread", GetExitCodeThread);
DECLARE_CRT_EXPORT("GetCurrentProcess", GetCurrentProcess);

DECLARE_CRT_EXPORT("LsaNtStatusToWinError", LsaNtStatusToWinError);

DECLARE_CRT_EXPORT("SetThreadToken", SetThreadToken);

DECLARE_CRT_EXPORT("InterlockedDecrement", InterlockedDecrement);

DECLARE_CRT_EXPORT("InterlockedIncrement", InterlockedIncrement);

DECLARE_CRT_EXPORT("InterlockedCompareExchange", InterlockedCompareExchange);

DECLARE_CRT_EXPORT("CreateSemaphoreW", CreateSemaphoreW);

DECLARE_CRT_EXPORT("AcquireSRWLockExclusive", AcquireSRWLockExclusive);

DECLARE_CRT_EXPORT("AcquireSRWLockShared", AcquireSRWLockShared);

DECLARE_CRT_EXPORT("InitializeSRWLock", InitializeSRWLock);

DECLARE_CRT_EXPORT("ReleaseSRWLockExclusive", ReleaseSRWLockExclusive);

DECLARE_CRT_EXPORT("ReleaseSRWLockShared", ReleaseSRWLockShared);

DECLARE_CRT_EXPORT("SetThreadpoolTimer", SetThreadpoolTimer);

DECLARE_CRT_EXPORT("WaitForThreadpoolTimerCallbacks", WaitForThreadpoolTimerCallbacks);

DECLARE_CRT_EXPORT("GetCurrentThreadId", GetCurrentThreadId);

DECLARE_CRT_EXPORT("GetCurrentProcessId", GetCurrentProcessId);

DECLARE_CRT_EXPORT("ProcessIdToSessionId", ProcessIdToSessionId);
