#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <dlfcn.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "mpclient.h"

#ifdef __x86_64__

extern struct thing *__start_RtlExecuteHandlerForExceptionSection;
extern struct thing *__stop_RtlExecuteHandlerForExceptionSection;
extern struct thing *__start_RtlDispatchExceptionSection;
extern struct thing *__stop_RtlDispatchExceptionSection;
extern struct thing *__start_RaiseExceptionSection;
extern struct thing *__stop_RaiseExceptionSection;

EXCEPTION_DISPOSITION WINAPI ExceptionHandler(struct _EXCEPTION_RECORD *ExceptionRecord,
                                              struct _EXCEPTION_FRAME *EstablisherFrame,
                                              struct _CONTEXT *ContextRecord,
                                              struct _EXCEPTION_FRAME **DispatcherContext) {
    LogMessage("Toplevel Exception Handler Caught Exception");
    abort();
}

#define RVA(m, b) ((PVOID)((ULONG_PTR)(b) + (ULONG_PTR)(m)))

/* ALIGNMENT MACROS */
#define ALIGN_DOWN_BY(size, align) ((ULONG_PTR)(size) & ~((ULONG_PTR)(align) - 1))
#define ALIGN_UP_BY(size, align) (ALIGN_DOWN_BY(((ULONG_PTR)(size) + (align) - 1), align))
#define ALIGN_UP_POINTER_BY(ptr, align) ((PVOID)ALIGN_UP_BY(ptr, align))

enum {
    RTL_EXECUTE_HANDLER_FOR_EXCEPTION = 0,
    RTL_DISPATCH_EXCEPTION,
    RAISE_EXCEPTION,
    MAIN_FUNCTION
};

PCONTEXT MSContextPtrs[3] = {0};


STATIC WINAPI

DWORD64 __inline GetReg(PCONTEXT Context, BYTE Reg) {
    return ((DWORD64 *) (&Context->Rax))[Reg];
}


STATIC WINAPI

void __inline SetReg(PCONTEXT Context, BYTE Reg, DWORD64 Value) {
    ((DWORD64 *) (&Context->Rax))[Reg] = Value;
}

STATIC WINAPI

VOID __inline SetRegFromStackValue(PCONTEXT Context,
                                   PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
                                   BYTE Reg,
                                   PDWORD64 ValuePointer) {
    SetReg(Context, Reg, *ValuePointer);
    if (ContextPointers != NULL) {
        ContextPointers->DUMMYUNIONNAME2.IntegerContext[Reg] = ValuePointer;
    }
}

STATIC WINAPI

__inline VOID SetXmmReg(PCONTEXT Context,
                        BYTE Reg,
                        M128A Value) {
    ((M128A *) (&Context->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Xmm0))[Reg] = Value;
}

STATIC WINAPI

__inline VOID SetXmmRegFromStackValue(PCONTEXT Context,
                                      PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
                                      BYTE Reg,
                                      M128A *ValuePointer) {
    SetXmmReg(Context, Reg, *ValuePointer);
    if (ContextPointers != NULL) {
        ContextPointers->DUMMYUNIONNAME.FloatingContext[Reg] = ValuePointer;
    }
}

STATIC WINAPI

VOID __inline PopReg(PCONTEXT Context,
                     PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
                     BYTE Reg) {
    SetRegFromStackValue(Context, ContextPointers, Reg, (PDWORD64) Context->Rsp);
    Context->Rsp += sizeof(DWORD64);
}

STATIC WINAPI

__inline ULONG UnwindOpSlots(UNWIND_CODE UnwindCode) {
    static const UCHAR UnwindOpExtraSlotTable[] =
            {
                    0, // UWOP_PUSH_NONVOL
                    1, // UWOP_ALLOC_LARGE (or 3, special cased in lookup code)
                    0, // UWOP_ALLOC_SMALL
                    0, // UWOP_SET_FPREG
                    1, // UWOP_SAVE_NONVOL
                    2, // UWOP_SAVE_NONVOL_FAR
                    1, // UWOP_EPILOG // previously UWOP_SAVE_XMM
                    2, // UWOP_SPARE_CODE // previously UWOP_SAVE_XMM_FAR
                    1, // UWOP_SAVE_XMM128
                    2, // UWOP_SAVE_XMM128_FAR
                    0, // UWOP_PUSH_MACHFRAME
                    2, // UWOP_SET_FPREG_LARGE
            };

    if ((UnwindCode.UnwindOp == UWOP_ALLOC_LARGE) &&
        (UnwindCode.OpInfo != 0)) {
        return 3;
    } else {
        return UnwindOpExtraSlotTable[UnwindCode.UnwindOp] + 1;
    }
}

STATIC WINAPI

PVOID RtlPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage) {
    PVOID ImageBase;

    DebugLog("%p %p", PcValue, BaseOfImage);

    if ((ULONG_PTR) PcValue >= (ULONG_PTR) image.image &&
        (ULONG_PTR) PcValue < (ULONG_PTR) image.image + image.size) {
        ImageBase = image.image;
    } else {
        // If we end up here, PcValue is probably somewhere in libpeloader.a
        ImageBase = NULL;
    }

    *BaseOfImage = ImageBase;

    return ImageBase;
}

// Shamelessly copy-pasted from ReactOs
// (https://doxygen.reactos.org/d8/d2f/unwind_8c.html#ae54b6e92ac33487731d412097a83cf7a)

STATIC WINAPI

PRUNTIME_FUNCTION RtlLookupFunctionTable(DWORD64 ControlPc,
                                         PDWORD64 ImageBase,
                                         PULONG Length) {
    DebugLog("");
    ULONG Size;

    PVOID Table = NULL;
    size_t NumberOfSections = image.nt_hdr->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(image.nt_hdr);

    /* Find corresponding file header from code address */
    if (!RtlPcToFileHeader((PVOID) ControlPc, (PVOID *) ImageBase)) {
        /* Nothing found */
        return NULL;
    }

    /* Locate the exception directory */
    for (int i = 0; i < NumberOfSections; Section++) {
        if (strncmp(Section->Name, ".pdata", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            Table = (PRUNTIME_FUNCTION) ((uintptr_t) image.image + Section->VirtualAddress);
            Size = (ULONG) Section->Misc.VirtualSize;
            break;
        }
    }

    if (Table != NULL)
        /* Return the number of entries */
        *Length = Size / sizeof(RUNTIME_FUNCTION);

    /* Return the address of the table */
    return Table;
}

STATIC

BOOL LookupPeloaderFunction(DWORD64 ControlPc, PRUNTIME_FUNCTION FunctionEntry) {
    Dl_info *info;
    int dladdr_result;

    /* Check if we are unwinding a libpeloader function */
    if (ControlPc >= (DWORD64) &__start_RtlExecuteHandlerForExceptionSection &&
        ControlPc <= (DWORD64) &__stop_RtlExecuteHandlerForExceptionSection) {
        FunctionEntry->BeginAddress = (uintptr_t) &__start_RtlExecuteHandlerForExceptionSection;
        FunctionEntry->EndAddress = (uintptr_t) &__stop_RtlExecuteHandlerForExceptionSection;
        FunctionEntry->UnwindData = RTL_EXECUTE_HANDLER_FOR_EXCEPTION;
        return TRUE;
    }

    if (ControlPc >= (DWORD64) &__start_RtlDispatchExceptionSection &&
        ControlPc <= (DWORD64) &__stop_RtlDispatchExceptionSection) {
        FunctionEntry->BeginAddress = (uintptr_t) &__start_RtlDispatchExceptionSection;
        FunctionEntry->EndAddress = (uintptr_t) &__stop_RtlDispatchExceptionSection;
        FunctionEntry->UnwindData = RTL_DISPATCH_EXCEPTION;
        return TRUE;
    }

    if (ControlPc >= (DWORD64) &__start_RaiseExceptionSection &&
        ControlPc <= (DWORD64) &__stop_RaiseExceptionSection) {
        FunctionEntry->BeginAddress = (uintptr_t) &__start_RaiseExceptionSection;
        FunctionEntry->EndAddress = (uintptr_t) &__stop_RaiseExceptionSection;
        FunctionEntry->UnwindData = RAISE_EXCEPTION;
        return TRUE;
    }

    /*
     * If we passed the previous ifs and dladdr returns a not-null value, it means we unwound till main
     * and we can safely abort (uncaught exception)
     */
    info = (Dl_info *) calloc(1, sizeof(Dl_info));
    dladdr_result = dladdr((void *) ControlPc, info);
    if (dladdr_result != 0) {
        FunctionEntry->BeginAddress = 0;
        FunctionEntry->EndAddress = 0;
        FunctionEntry->UnwindData = MAIN_FUNCTION;
        free(info);
        return TRUE;
    }

    free(info);
    return FALSE;
}

// Shamelessly copy-pasted from ReactOs and re-adapted
// (https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a8de4364298b3176587d39e35e644a3c0)

STATIC WINAPI

PRUNTIME_FUNCTION RtlLookupFunctionEntry(DWORD64 ControlPc,
                                         PDWORD64 ImageBase,
                                         PUNWIND_HISTORY_TABLE HistoryTable) {
    DebugLog("%p, %p", ControlPc, ImageBase);
    PRUNTIME_FUNCTION FunctionTable, PDataFunctionEntry;
    BOOL PeloaderFunctionEntryFound;
    ULONG TableLength;
    ULONG IndexLo, IndexHi, IndexMid;

    PRUNTIME_FUNCTION FunctionEntry = (PRUNTIME_FUNCTION) malloc(sizeof(RUNTIME_FUNCTION));
    if (!FunctionEntry) {
        return NULL;
    }

    PeloaderFunctionEntryFound = LookupPeloaderFunction(ControlPc, FunctionEntry);

    if (PeloaderFunctionEntryFound) {
        return FunctionEntry;
    }

    /* Find the corresponding table */
    FunctionTable = RtlLookupFunctionTable(ControlPc, ImageBase, &TableLength);

    /* Fail, if no table is found */
    if (!FunctionTable) {
        return NULL;
    }

    /* Use relative virtual address */
    ControlPc -= *ImageBase;

    /* Do a binary search */
    IndexLo = 0;
    IndexHi = TableLength;
    while (IndexHi > IndexLo) {
        IndexMid = (IndexLo + IndexHi) / 2;
        PDataFunctionEntry = &FunctionTable[IndexMid];

        if (ControlPc < PDataFunctionEntry->BeginAddress) {
            /* Continue search in lower half */
            IndexHi = IndexMid;
        } else if (ControlPc >= PDataFunctionEntry->EndAddress) {
            /* Continue search in upper half */
            IndexLo = IndexMid + 1;
        } else {
            /* ControlPc is within limits, return entry */
            FunctionEntry->BeginAddress = PDataFunctionEntry->BeginAddress;
            FunctionEntry->EndAddress = PDataFunctionEntry->EndAddress;
            FunctionEntry->UnwindData = PDataFunctionEntry->UnwindData;
            return FunctionEntry;
        }
    }

    /* Nothing found, return NULL */
    return NULL;
}

// Shamelessly copy-pasted from ReactOS
// (https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a57ef599c611dcdefb93d5bda32af4819)

STATIC WINAPI

ULONG64 GetEstablisherFrame(
        PCONTEXT Context,
        PUNWIND_INFO UnwindInfo,
        ULONG_PTR CodeOffset) {

    DebugLog("");

    ULONG i;

    /* Check if we have a frame register */
    if (UnwindInfo->FrameRegister == 0) {
        /* No frame register means we use Rsp */
        return Context->Rsp;
    }

    if ((CodeOffset >= UnwindInfo->SizeOfProlog) ||
        ((UnwindInfo->Flags & UNW_FLAG_CHAININFO) != 0)) {
        return GetReg(Context, UnwindInfo->FrameRegister) -
               UnwindInfo->FrameOffset * 16;
    }

    /* Loop all unwind ops */
    for (i = 0;
         i < UnwindInfo->CountOfCodes;
         i += UnwindOpSlots(UnwindInfo->UnwindCode[i])) {
        /* Check for SET_FPREG */
        if (UnwindInfo->UnwindCode[i].UnwindOp == UWOP_SET_FPREG) {
            return GetReg(Context, UnwindInfo->FrameRegister) -
                   UnwindInfo->FrameOffset * 16;
        }
    }

    return Context->Rsp;
}

// Shamelessly copy-pasted from ReactOS
// (https://doxygen.reactos.org/d8/d2f/unwind_8c.html#ab1254c449095abb6946019d9f3a00fd7)

STATIC WINAPI

BOOLEAN RtlpTryToUnwindEpilog(
        PCONTEXT Context,
        PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
        ULONG64 ImageBase,
        PRUNTIME_FUNCTION FunctionEntry) {
    CONTEXT LocalContext;
    BYTE *InstrPtr;
    DWORD Instr;
    BYTE Reg, Mod;
    ULONG64 EndAddress;

    /* Make a local copy of the context */
    LocalContext = *Context;

    InstrPtr = (BYTE *) LocalContext.Rip;

    /* Check if first instruction of epilog is "add rsp, x" */
    Instr = *(DWORD *) InstrPtr;
    if ((Instr & 0x00fffdff) == 0x00c48148) {
        if ((Instr & 0x0000ff00) == 0x8300) {
            /* This is "add rsp, 0x??" */
            LocalContext.Rsp += Instr >> 24;
            InstrPtr += 4;
        } else {
            /* This is "add rsp, 0x???????? */
            LocalContext.Rsp += *(DWORD *) (InstrPtr + 3);
            InstrPtr += 7;
        }
    }
        /* Check if first instruction of epilog is "lea rsp, ..." */
    else if ((Instr & 0x38fffe) == 0x208d48) {
        /* Get the register */
        Reg = ((Instr << 8) | (Instr >> 16)) & 0x7;

        LocalContext.Rsp = GetReg(&LocalContext, Reg);

        /* Get adressing mode */
        Mod = (Instr >> 22) & 0x3;
        if (Mod == 0) {
            /* No displacement */
            InstrPtr += 3;
        } else if (Mod == 1) {
            /* 1 byte displacement */
            LocalContext.Rsp += Instr >> 24;
            InstrPtr += 4;
        } else if (Mod == 2) {
            /* 4 bytes displacement */
            LocalContext.Rsp += *(DWORD *) (InstrPtr + 3);
            InstrPtr += 7;
        }
    }

    /* Loop the following instructions before the ret */
    EndAddress = FunctionEntry->EndAddress + ImageBase - 1;
    while ((DWORD64) InstrPtr < EndAddress) {
        Instr = *(DWORD *) InstrPtr;

        /* Check for a simple pop */
        if ((Instr & 0xf8) == 0x58) {
            /* Opcode pops a basic register from stack */
            Reg = Instr & 0x7;
            PopReg(&LocalContext, ContextPointers, Reg);
            InstrPtr++;
            continue;
        }

        /* Check for REX + pop */
        if ((Instr & 0xf8fb) == 0x5841) {
            /* Opcode is pop r8 .. r15 */
            Reg = ((Instr >> 8) & 0x7) + 8;
            PopReg(&LocalContext, ContextPointers, Reg);
            InstrPtr += 2;
            continue;
        }

        /* Opcode not allowed for Epilog */
        return FALSE;
    }

    // check for popfq

    // also allow end with jmp imm, jmp [target], iretq

    /* Check if we are at the ret instruction */
    if ((DWORD64) InstrPtr != EndAddress) {
        /* If we went past the end of the function, something is broken! */
        //ASSERT((DWORD64)InstrPtr <= EndAddress);
        return FALSE;
    }

    /* Make sure this is really a ret instruction */
    if (*InstrPtr != 0xc3) {
        //ASSERT(FALSE);
        return FALSE;
    }

    /* Unwind is finished, pop new Rip from Stack */
    LocalContext.Rip = *(DWORD64 *) LocalContext.Rsp;
    LocalContext.Rsp += sizeof(DWORD64);

    *Context = LocalContext;
    return TRUE;
}

STATIC WINAPI

VOID UnwindLibPeloaderFunction(PRUNTIME_FUNCTION pFunction, PCONTEXT pContext) {
    PCONTEXT LibPeloaderFunctionContext = MSContextPtrs[pFunction->UnwindData];
    pContext->Rsp = LibPeloaderFunctionContext->Rsp;
    pContext->Rbp = LibPeloaderFunctionContext->Rbp;
    pContext->Rip = LibPeloaderFunctionContext->Rip;
}

// Shamelessly copy-pasted from ReactOS and re-adapted
// (https://doxygen.reactos.org/d8/d2f/unwind_8c.html#a03c91b6c437066272ebc2c2fff051a4c)

STATIC WINAPI

PEXCEPTION_ROUTINE RtlVirtualUnwind(
        ULONG HandlerType,
        ULONG64 ImageBase,
        ULONG64 ControlPc,
        PRUNTIME_FUNCTION FunctionEntry,
        PCONTEXT Context,
        PVOID *HandlerData,
        PULONG64 EstablisherFrame,
        PKNONVOLATILE_CONTEXT_POINTERS ContextPointers) {
    PUNWIND_INFO UnwindInfo;
    ULONG_PTR CodeOffset;
    ULONG i, Offset;
    UNWIND_CODE UnwindCode;
    BYTE Reg;
    PULONG LanguageHandler;

    DebugLog("");

    // peloader functions do not have an handler
    if (FunctionEntry->UnwindData == RTL_EXECUTE_HANDLER_FOR_EXCEPTION ||
        FunctionEntry->UnwindData == RTL_DISPATCH_EXCEPTION ||
        FunctionEntry->UnwindData == RAISE_EXCEPTION) {
        UnwindLibPeloaderFunction(FunctionEntry, Context);
        return NULL;
    }

    // If we reached main, abort.
    if (FunctionEntry->UnwindData == MAIN_FUNCTION) {
        return (PEXCEPTION_ROUTINE) ExceptionHandler;
    }

    /* Use relative virtual address */
    ControlPc -= ImageBase;

    /* Sanity checks */
    if ((ControlPc < FunctionEntry->BeginAddress) ||
        (ControlPc >= FunctionEntry->EndAddress)) {
        return NULL;
    }

    /* Get a pointer to the unwind info */
    UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);

    /* Check for chained info */
    if (UnwindInfo->Flags & UNW_FLAG_CHAININFO) {
        //UNIMPLEMENTED_DBGBREAK();

        /* See https://docs.microsoft.com/en-us/cpp/build/chained-unwind-info-structures */
        FunctionEntry = (PRUNTIME_FUNCTION) &(UnwindInfo->UnwindCode[(UnwindInfo->CountOfCodes + 1) & ~1]);
        UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);
    }

    /* The language specific handler data follows the unwind info */
    LanguageHandler = ALIGN_UP_POINTER_BY(&UnwindInfo->UnwindCode[UnwindInfo->CountOfCodes], sizeof(ULONG));
    *HandlerData = (LanguageHandler + 1);

    /* Calculate relative offset to function start */
    CodeOffset = ControlPc - FunctionEntry->BeginAddress;

    *EstablisherFrame = GetEstablisherFrame(Context, UnwindInfo, CodeOffset);

    // Check if we are in the function epilog and try to finish it
    if (CodeOffset > UnwindInfo->SizeOfProlog) {
        if (RtlpTryToUnwindEpilog(Context, ContextPointers, ImageBase, FunctionEntry)) {
            // There's no exception routine
            return NULL;
        }
    }

    /* Skip all Ops with an offset greater than the current Offset */
    i = 0;
    while ((i < UnwindInfo->CountOfCodes) &&
           (UnwindInfo->UnwindCode[i].CodeOffset > CodeOffset)) {
        i += UnwindOpSlots(UnwindInfo->UnwindCode[i]);
    }

    /* Process the remaining unwind ops */
    while (i < UnwindInfo->CountOfCodes) {
        UnwindCode = UnwindInfo->UnwindCode[i];
        switch (UnwindCode.UnwindOp) {
            case UWOP_PUSH_NONVOL:
                Reg = UnwindCode.OpInfo;
                PopReg(Context, ContextPointers, Reg);
                i++;
                break;

            case UWOP_ALLOC_LARGE:
                if (UnwindCode.OpInfo) {
                    Offset = *(ULONG *) (&UnwindInfo->UnwindCode[i + 1]);
                    Context->Rsp += Offset;
                    i += 3;
                } else {
                    Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
                    Context->Rsp += Offset * 8;
                    i += 2;
                }
                break;

            case UWOP_ALLOC_SMALL:
                Context->Rsp += (UnwindCode.OpInfo + 1) * 8;
                i++;
                break;

            case UWOP_SET_FPREG:
                Reg = UnwindInfo->FrameRegister;
                Context->Rsp = GetReg(Context, Reg) - UnwindInfo->FrameOffset * 16;
                i++;
                break;

            case UWOP_SAVE_NONVOL:
                Reg = UnwindCode.OpInfo;
                Offset = *(USHORT *) (&UnwindInfo->UnwindCode[i + 1]);
                SetRegFromStackValue(Context, ContextPointers, Reg, (DWORD64 *) Context->Rsp + Offset);
                i += 2;
                break;

            case UWOP_SAVE_NONVOL_FAR:
                Reg = UnwindCode.OpInfo;
                Offset = *(ULONG *) (&UnwindInfo->UnwindCode[i + 1]);
                SetRegFromStackValue(Context, ContextPointers, Reg, (DWORD64 *) Context->Rsp + Offset);
                i += 3;
                break;

            case UWOP_EPILOG:
                i += 1;
                break;

            case UWOP_SPARE_CODE:
                // ASSERT(FALSE);
                i += 2;
                break;

            case UWOP_SAVE_XMM128:
                Reg = UnwindCode.OpInfo;
                Offset = *(USHORT *) (&UnwindInfo->UnwindCode[i + 1]);
                SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A *) (Context->Rsp + Offset));
                i += 2;
                break;

            case UWOP_SAVE_XMM128_FAR:
                Reg = UnwindCode.OpInfo;
                Offset = *(ULONG *) (&UnwindInfo->UnwindCode[i + 1]);
                SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A *) (Context->Rsp + Offset));
                i += 3;
                break;

            case UWOP_PUSH_MACHFRAME:
                /* OpInfo is 1, when an error code was pushed, otherwise 0. */
                Context->Rsp += UnwindCode.OpInfo * sizeof(DWORD64);

                /* Now pop the MACHINE_FRAME (Yes, "magic numbers", deal with it) */
                Context->Rip = *(PDWORD64) (Context->Rsp + 0x00);
                Context->SegCs = *(PDWORD64) (Context->Rsp + 0x08);
                Context->EFlags = *(PDWORD64) (Context->Rsp + 0x10);
                Context->SegSs = *(PDWORD64) (Context->Rsp + 0x20);
                Context->Rsp = *(PDWORD64) (Context->Rsp + 0x18);
                // ASSERT((i + 1) == UnwindInfo->CountOfCodes);
                goto Exit;
        }
    }

    /* Unwind is finished, pop new Rip from Stack */
    if (Context->Rsp != 0) {
        Context->Rip = *(DWORD64 *) Context->Rsp;
        Context->Rsp += sizeof(DWORD64);
    }

    Exit:

    /* Check if we have a handler and return it */
    if (UnwindInfo->Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        return RVA(ImageBase, *LanguageHandler);
    }

    return NULL;
}

STATIC WINAPI

EXCEPTION_DISPOSITION __attribute__ ((noinline, section ("RtlExecuteHandlerForExceptionSection")))
RtlExecuteHandlerForException(PEXCEPTION_RECORD pFunction,
                              PVOID EstablisherFrame,
                              PCONTEXT lpContext,
                              PDISPATCHER_CONTEXT lpDispatcherContext) {
    DebugLog("");
    EXCEPTION_DISPOSITION ExceptionDisposition;
    // Store the return address in the CONTEXT structure (useful during the unwinding)
    PCONTEXT pContext = MSContextPtrs[RTL_EXECUTE_HANDLER_FOR_EXCEPTION];
    pContext->Rip = (DWORD64) __builtin_return_address(0);

    PDISPATCHER_CONTEXT DispatcherContext = lpDispatcherContext;

    ExceptionDisposition = DispatcherContext->LanguageHandler(pFunction, EstablisherFrame, lpContext, lpDispatcherContext);
    free(DispatcherContext->FunctionEntry);

    return ExceptionDisposition;
}

STATIC WINAPI

VOID RtlRestoreContext(PCONTEXT pContext, PEXCEPTION_RECORD pExceptionRecord) {
    PVOID WINAPI (*CxxCallCatchBlock)(PEXCEPTION_RECORD ExceptionRecord);
    PVOID RestoreExecutionPoint;
    if (pExceptionRecord != NULL) {
        if (pExceptionRecord->ExceptionCode == STATUS_UNWIND_CONSOLIDATE) {
            if (pExceptionRecord->NumberParameters > 1) {
                CxxCallCatchBlock = pExceptionRecord->ExceptionInformation[0];
                RestoreExecutionPoint = CxxCallCatchBlock(pExceptionRecord);
                pContext->Rip = (DWORD64) RestoreExecutionPoint;
            }
        } else {
            // TODO: implement this
            __debugbreak();
        }
    }

    // Consolidate frames and restore execution
    asm("mov %[context], %%rbp\n"
        "mov 248(%%rbp), %%rax\n" // Context[RIP] -> RAX
        "mov 152(%%rbp), %%rsp\n" // Change stack pointer
        "push %%rax\n"            // push new return value
        "fxrstor 256(%%rbp)\n"
        "movaps 416(%%rbp), %%xmm0\n"
        "movaps 432(%%rbp), %%xmm1\n"
        "movaps 448(%%rbp), %%xmm2\n"
        "movaps 464(%%rbp), %%xmm3\n"
        "movaps 480(%%rbp), %%xmm4\n"
        "movaps 496(%%rbp), %%xmm5\n"
        "movaps 512(%%rbp), %%xmm6\n"
        "movaps 528(%%rbp), %%xmm7\n"
        "movaps 544(%%rbp), %%xmm8\n"
        "movaps 560(%%rbp), %%xmm9\n"
        "movaps 576(%%rbp), %%xmm10\n"
        "movaps 592(%%rbp), %%xmm11\n"
        "movaps 608(%%rbp), %%xmm12\n"
        "movaps 624(%%rbp), %%xmm13\n"
        "movaps 640(%%rbp), %%xmm14\n"
        "movaps 656(%%rbp), %%xmm15\n"
        "ldmxcsr 52(%%rbp)\n"
        "mov 120(%%rbp), %%rax\n"
        "mov 128(%%rbp), %%rcx\n"
        "mov 136(%%rbp), %%rdx\n"
        "mov 144(%%rbp), %%rbx\n"
        "mov 168(%%rbp), %%rsi\n"
        "mov 176(%%rbp), %%rdi\n"
        "mov 184(%%rbp), %%r8\n"
        "mov 192(%%rbp), %%r9\n"
        "mov 200(%%rbp), %%r10\n"
        "mov 208(%%rbp), %%r11\n"
        "mov 216(%%rbp), %%r12\n"
        "mov 224(%%rbp), %%r13\n"
        "mov 232(%%rbp), %%r14\n"
        "mov 240(%%rbp), %%r15\n"
        "mov 160(%%rbp), %%rbp\n"
        "ret":: [context] "r"((uintptr_t) pContext));
}

STATIC WINAPI

BOOL RtlUnwindInternal(
        PVOID TargetFrame,
        PVOID TargetIp,
        PEXCEPTION_RECORD ExceptionRecord,
        PVOID ReturnValue,
        PCONTEXT ContextRecord,
        struct _UNWIND_HISTORY_TABLE *HistoryTable,
        ULONG HandlerType) {
    DISPATCHER_CONTEXT DispatcherContext;
    PEXCEPTION_ROUTINE ExceptionRoutine;
    EXCEPTION_DISPOSITION Disposition;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG_PTR StackLow, StackHigh;
    ULONG64 ImageBase, EstablisherFrame;
    CONTEXT UnwindContext;

    /* Copy the context */
    UnwindContext = *ContextRecord;

    /* Set up the constant fields of the dispatcher context */
    DispatcherContext.ContextRecord = ContextRecord;
    DispatcherContext.HistoryTable = HistoryTable;
    DispatcherContext.TargetIp = (ULONG64) TargetIp;

    /* Start looping */
    while (TRUE) {
        /* Lookup the FunctionEntry for the current RIP */
        FunctionEntry = RtlLookupFunctionEntry(UnwindContext.Rip, &ImageBase, NULL);
        if (FunctionEntry == NULL) {
            /* No function entry, so this must be a leaf function. Pop the return address from the stack.
               Note: this can happen after the first frame as the result of an exception */
            UnwindContext.Rip = *(DWORD64 *) UnwindContext.Rsp;
            UnwindContext.Rsp += sizeof(DWORD64);
            continue;
        }

        /* Do a virtual unwind to get the next frame */
        ExceptionRoutine = RtlVirtualUnwind(HandlerType,
                                            ImageBase,
                                            UnwindContext.Rip,
                                            FunctionEntry,
                                            &UnwindContext,
                                            &DispatcherContext.HandlerData,
                                            &EstablisherFrame,
                                            NULL);

        /* Check if we have an exception routine */
        if (ExceptionRoutine != NULL) {
            /* Check if this is the target frame */
            if (EstablisherFrame == (ULONG64) TargetFrame) {
                /* Set flag to inform the language handler */
                ExceptionRecord->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
            }

            /* Set up the variable fields of the dispatcher context */
            DispatcherContext.ControlPc = ContextRecord->Rip;
            DispatcherContext.ImageBase = ImageBase;
            DispatcherContext.FunctionEntry = FunctionEntry;
            DispatcherContext.LanguageHandler = ExceptionRoutine;
            DispatcherContext.EstablisherFrame = EstablisherFrame;
            DispatcherContext.ScopeIndex = 0;

            /* Store the return value in the unwind context */
            UnwindContext.Rax = (ULONG64) ReturnValue;

            /* Loop all nested handlers */
            do {
                /* Call the language specific handler */
                Disposition = ExceptionRoutine(ExceptionRecord,
                                               (PVOID) EstablisherFrame,
                                               &UnwindContext,
                                               &DispatcherContext);

                /* Clear exception flags for the next iteration */
                ExceptionRecord->ExceptionFlags &= ~(EXCEPTION_TARGET_UNWIND |
                                                     EXCEPTION_COLLIDED_UNWIND);

                /* Check if we do exception handling */
                if (HandlerType == UNW_FLAG_EHANDLER) {
                    if (Disposition == ExceptionContinueExecution) {
                        /* Check if it was non-continuable */
                        if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
                            __debugbreak();
                            // RtlRaiseStatus(EXCEPTION_NONCONTINUABLE_EXCEPTION);
                        }

                        /* Execution continues */
                        return TRUE;
                    } else if (Disposition == ExceptionNestedException) {
                        __debugbreak();
                    }
                }

                if (Disposition == ExceptionCollidedUnwind) {
                    __debugbreak();
                }

                /* This must be ExceptionContinueSearch now */
                if (Disposition != ExceptionContinueSearch) {
                    __debugbreak();
                    // RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
                }
            } while (ExceptionRecord->ExceptionFlags & EXCEPTION_COLLIDED_UNWIND);
        }

        if (EstablisherFrame == (ULONG64) TargetFrame) {
            break;
        }

        /* We have successfully unwound a frame. Copy the unwind context back. */
        *ContextRecord = UnwindContext;
    }

    if (ExceptionRecord->ExceptionCode != STATUS_UNWIND_CONSOLIDATE) {
        ContextRecord->Rip = (ULONG64) TargetIp;
    }

    /* Set the return value */
    ContextRecord->Rax = (ULONG64) ReturnValue;

    /* Restore the context */
    RtlRestoreContext(ContextRecord, ExceptionRecord);
    __debugbreak();

    /* Should never get here! */
    return FALSE;
}

STATIC WINAPI

BOOL RtlUnwindEx(
        PVOID TargetFrame,
        PVOID TargetIp,
        PEXCEPTION_RECORD ExceptionRecord,
        PVOID ReturnValue,
        PCONTEXT ContextRecord,
        struct _UNWIND_HISTORY_TABLE *HistoryTable) {
    EXCEPTION_RECORD LocalExceptionRecord;
    ucontext_t Context;
    CONTEXT MSContext = {0};

    uintptr_t ControlPc;

    // Save current registers
    if (getcontext(&Context) != 0) {
        abort();
    }
    nix_2_ms_context_swap(&Context, &MSContext);

    /*
     * Get the return address of the current (RaiseException) function.
     * ControlPc will point to the body of some DLL's function,
     * which called RaiseException.
     */
    ControlPc = (uintptr_t) __builtin_return_address(0);
    /*
     * Now, we have to manually unwind the context to the previous call (VCRUTIMEVXX!_CxxThrowException),
     * since we do not have a RUNTIME_FUNCTION available for the current (RaiseException)
     * function, and then we cannot use RtlVirtualUnwind on it.
     * After we unwound to the previous frame, we call DispatchContext and we should be
     * able to loop back starting from it.
     */
    uintptr_t *rbp = ((uintptr_t *) (__builtin_frame_address(0)))[0];
    uintptr_t *rsp = ((uintptr_t) (__builtin_frame_address(0))) + 0x8 + 0x8; // Find rsp + 0x8 + 0x8 (rsi + rdi maybe?)

    MSContext.Rsp = (DWORD64) rsp;
    MSContext.Rbp = (DWORD64) rbp;
    MSContext.Rip = (DWORD64) ControlPc;

    /* Check if we have an exception record */
    if (ExceptionRecord == NULL) {
        /* No exception record was passed, so set up a local one */
        LocalExceptionRecord.ExceptionCode = STATUS_UNWIND;
        LocalExceptionRecord.ExceptionAddress = (PVOID) ContextRecord->Rip;
        LocalExceptionRecord.ExceptionRecord = NULL;
        LocalExceptionRecord.NumberParameters = 0;
        ExceptionRecord = &LocalExceptionRecord;
    }

    /* Call the internal function */
    RtlUnwindInternal(TargetFrame,
                      TargetIp,
                      ExceptionRecord,
                      ReturnValue,
                      &MSContext,
                      HistoryTable,
                      UNW_FLAG_UHANDLER);
}

STATIC WINAPI

BOOL __attribute__ ((noinline, section ("RtlDispatchExceptionSection")))
RtlDispatchException(PEXCEPTION_RECORD ExceptionRecord, CONTEXT *pContext) {
    DWORD64 ImageBase;
    PVOID HandlerData;
    ULONG64 EstablisherFrame;
    DISPATCHER_CONTEXT DispatcherContext;
    EXCEPTION_DISPOSITION Disposition;
    ucontext_t Context;
    PCONTEXT pMSContext;
    //CONTEXT UnwindContext = { 0 };

    //CopyContext(pContext, &UnwindContext);

    DebugLog("%p, %p", ExceptionRecord, pContext);
    // Store the return address in the CONTEXT structure (useful during the unwinding)
    PCONTEXT pRtlDispatchMSContext = MSContextPtrs[RTL_DISPATCH_EXCEPTION];
    pRtlDispatchMSContext->Rip = (DWORD64) __builtin_return_address(0);

    while (TRUE) {
        // Take RIP from the CONTEXT
        DWORD64 ControlPc = pContext->Rip;

        // RtlLookupFunctionEntry passing RIP as argument
        PRUNTIME_FUNCTION RuntimeFunction = RtlLookupFunctionEntry(ControlPc, &ImageBase, NULL);
        // Check if a RUNTIME_FUNCTION is associated with it
        if (!RuntimeFunction) {
            pContext->Rip = pContext->Rsp;
            pContext->Rsp = pContext->Rsp + 0x8;
            continue;
        }

        DispatcherContext.FunctionEntry = RuntimeFunction;

        // TODO: Copy the CONTEXT?

        // Unwind to the caller
        PEXCEPTION_ROUTINE ExceptionRoutine = RtlVirtualUnwind(UNW_FLAG_EHANDLER,
                                                               ImageBase,
                                                               ControlPc,
                                                               RuntimeFunction,
                                                               pContext,
                                                               &DispatcherContext.HandlerData,
                                                               &EstablisherFrame,
                                                               NULL);

        // Check if an EXCEPTION_ROUTINE has been found
        if (ExceptionRoutine != NULL) {

            // Initialize the dispatcher context
            DispatcherContext.ControlPc = ControlPc;
            DispatcherContext.ImageBase = ImageBase;
            DispatcherContext.EstablisherFrame = EstablisherFrame;
            DispatcherContext.ContextRecord = pContext;
            DispatcherContext.LanguageHandler = ExceptionRoutine;
            DispatcherContext.ScopeIndex = 0;


            // Capture the context. We will need it during the unwinding
            pMSContext = (PCONTEXT) malloc(sizeof(CONTEXT));
            if (pMSContext == NULL) {
                return FALSE;
            }
            memset(pMSContext, 0, sizeof(CONTEXT));
            if (getcontext(&Context) != 0) {
                abort();
            }
            nix_2_ms_context_swap(&Context, pMSContext);
            MSContextPtrs[RTL_EXECUTE_HANDLER_FOR_EXCEPTION] = pMSContext;

            // Call the LanguageHandler
            Disposition = RtlExecuteHandlerForException(ExceptionRecord,
                                                        (PVOID) EstablisherFrame,
                                                        pContext,
                                                        &DispatcherContext);

            /* Clear exception flags for the next iteration */
            ExceptionRecord->ExceptionFlags &= ~(EXCEPTION_TARGET_UNWIND |
                                                 EXCEPTION_COLLIDED_UNWIND);

        }
    }
}

STATIC WINAPI

PVOID __attribute__ ((noinline, section ("RaiseExceptionSection")))
RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, PVOID Arguments) {
    uintptr_t ControlPc;
    uintptr_t CallerFrame;
    PUNWIND_INFO UnwindInfo;
    PRUNTIME_FUNCTION FunctionEntry;
    PEXCEPTION_ROUTINE ExceptionRoutine;
    KNONVOLATILE_CONTEXT_POINTERS ContextPointers;
    PULONG LanguageHandler;
    PVOID HandlerData;
    ULONG64 EstablisherFrame;
    ucontext_t Context;
    ucontext_t RtlDispatchExceptionContext;

    DebugLog("%#x, %#x, %#x", dwExceptionCode, dwExceptionFlags, nNumberOfArguments);

    NTSTATUS Status = STATUS_INVALID_DISPOSITION;
    CONTEXT MSContext = {0};
    PCONTEXT pRtlDispatchExceptionMSContext;
    PCONTEXT pRaiseExceptionMSContext;
    DWORD64 ImageBase = 0;

    EXCEPTION_RECORD ExceptionRecord = {
            .ExceptionCode = dwExceptionCode,
            .ExceptionFlags = dwExceptionFlags,
            .ExceptionAddress =  RaiseException,
            .NumberParameters = nNumberOfArguments,
    };

    // Setup Record
    memcpy(&ExceptionRecord.ExceptionInformation, Arguments, nNumberOfArguments * sizeof(long));

    // Save current registers
    if (getcontext(&Context) != 0) {
        abort();
    }
    nix_2_ms_context_swap(&Context, &MSContext);
    /*
     * Get the return address of the current (RaiseException) function.
     * ControlPc will point to the body of some DLL's function,
     * which called RaiseException.
     */
    ControlPc = (uintptr_t) __builtin_return_address(0);
    /*
     * Now, we have to manually unwind the context to the previous call (VCRUTIMEVXX!_CxxThrowException),
     * since we do not have a RUNTIME_FUNCTION available for the current (RaiseException)
     * function, and then we cannot use RtlVirtualUnwind on it.
     * After we unwound to the previous frame, we call DispatchContext and we should be
     * able to loop back starting from it.
     */
    uintptr_t *rbp = ((uintptr_t *) (__builtin_frame_address(0)))[0];
    uintptr_t *rsp = ((uintptr_t) (__builtin_frame_address(0))) + 0x8 + 0x8; // Find rsp + 0x8 + 0x8 (rsi + rdi maybe?)


    MSContext.Rsp = (DWORD64) rsp;
    MSContext.Rbp = (DWORD64) rbp;
    MSContext.Rip = (DWORD64) ControlPc;
    pRaiseExceptionMSContext = (PCONTEXT) malloc(sizeof(CONTEXT));
    if (pRaiseExceptionMSContext == NULL) {
        return FALSE;
    }
    memset(pRaiseExceptionMSContext, 0, sizeof(CONTEXT));
    pRaiseExceptionMSContext->Rsp = MSContext.Rsp;
    pRaiseExceptionMSContext->Rbp = MSContext.Rbp;
    pRaiseExceptionMSContext->Rip = MSContext.Rip;
    MSContextPtrs[RAISE_EXCEPTION] = pRaiseExceptionMSContext;

    /* Get the function entry of RaiseException caller */
    FunctionEntry = RtlLookupFunctionEntry((DWORD64) ControlPc,
                                           &ImageBase,
                                           NULL);

    // Check if we found the RuntimeFunction of VCRUTIMEVXX!_CxxThrowException
    if (FunctionEntry) {
        // Unwind to the caller of VCRUTIMEVXX!_CxxThrowException
        RtlVirtualUnwind(UNW_FLAG_EHANDLER,
                         ImageBase,
                         ControlPc,
                         FunctionEntry,
                         &MSContext,
                         &HandlerData,
                         &EstablisherFrame,
                         &ContextPointers);

        /*
         * Usually VCRUTIMEVXX!_CxxThrowException does not have a EXCEPTION_ROUTINE structure associated.
         * At this point, we can safely call RtlDispatchException passing as argument the EXCEPTION_RECORD of
         * VCRUTIMEVXX!_CxxThrowException and the CONTEXT unwound to the caller of VCRUTIMEVXX!_CxxThrowException,
         * which is some function defined in the DLL.
         */
        ExceptionRecord.ExceptionAddress = (PVOID) ControlPc;

        // Store the context before calling RtlDispatchException, which will be used during unwinding procedure
        pRtlDispatchExceptionMSContext = (PCONTEXT) malloc(sizeof(CONTEXT));
        if (pRtlDispatchExceptionMSContext == NULL) {
            return FALSE;
        }
        memset(pRtlDispatchExceptionMSContext, 0, sizeof(CONTEXT));
        if (getcontext(&RtlDispatchExceptionContext) != 0) {
            abort();
        }
        nix_2_ms_context_swap(&RtlDispatchExceptionContext, pRtlDispatchExceptionMSContext);
        MSContextPtrs[RTL_DISPATCH_EXCEPTION] = pRtlDispatchExceptionMSContext;
        // Dispatch the exception
        if (!RtlDispatchException(&ExceptionRecord, &MSContext)) {
            __debugbreak();
        } else {
            // Continue, go back to previous context
            // Status = ZwContinue(&Context, FALSE);
        }
    }

    finished:
    // I've never seen this reached, I'm not sure if it works.
    __debugbreak();
    return NULL;
}
#else
#ifndef NDEBUG

// You can use `call DumpExceptionChain()` in gdb, like !exchain in windbg if
// you need to debug exception handling.
VOID DumpExceptionChain(VOID) {
    PEXCEPTION_FRAME ExceptionList;
    DWORD Depth;

    // Fetch Exception List
    asm("mov %%fs:0, %[list]" : [list] "=r"(ExceptionList));

    DebugLog("ExceptionList %p, Dumping SEH Chain...", ExceptionList);

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                 Depth++, "",
                 ExceptionList,
                 ExceptionList->prev,
                 ExceptionList->handler);
    }
}

#endif

STATIC WINAPI

void RtlUnwind(PEXCEPTION_FRAME TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
{
    PEXCEPTION_FRAME ExceptionList;
    DWORD Depth;
    ucontext_t Context;

    DebugLog("%p, %p, %p, %p", TargetFrame, TargetIp, ExceptionRecord, ReturnValue);

    assert(ExceptionRecord);
    assert(TargetFrame);
    assert(TargetIp);

    ExceptionRecord->ExceptionFlags |= EH_UNWINDING;

    // Save current registers
    if (getcontext(&Context) != 0) {
        abort();
    }

    // This was suuuuuuper complicated to get right and make mpengine happy.
    Context.uc_mcontext.gregs[REG_EBP] = ((uintptr_t *)(__builtin_frame_address(0)))[0];
    Context.uc_mcontext.gregs[REG_EIP] = ((uintptr_t *)(__builtin_frame_address(0)))[1];
    Context.uc_mcontext.gregs[REG_ESP] = ((uintptr_t)(__builtin_frame_address(0))) + 8 + 16; // Find esp (+8) then skip args (+4*4)
    Context.uc_mcontext.gregs[REG_EAX] = ((uintptr_t)(ReturnValue));

    // Fetch Exception List
    asm("mov %%fs:0, %[list]" : [list] "=r"(ExceptionList));

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DWORD Result;
        DWORD Dispatch = 0;

        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                Depth++, "",
                ExceptionList,
                ExceptionList->prev,
                ExceptionList->handler);

        // You don't call the final handler, you just install the new context.
        if (ExceptionList == TargetFrame) {
            DebugLog("TargetFrame %p == ExceptionList %p, Restore Context", ExceptionList, TargetFrame);

            setcontext(&Context);

            // Should not reach here.
            __debugbreak();
        }

        // Call all handlers before the TargetFrame.
        Result = ExceptionList->handler(ExceptionRecord, ExceptionList, NULL, (PVOID) &Dispatch);

        DebugLog("%*s Result: %u, Dispatch: %p", Depth, "", Result, Dispatch);

        if (Result != ExceptionContinueSearch) {
            // I've never seen any other handler return code with mpengine.
            __debugbreak();
        }

        // Remove handler.
        asm("mov %[list], %%fs:0" :: [list] "r"(ExceptionList->prev));
    }

    // Unhandled C++ Exception?
    __debugbreak();
}

STATIC WINAPI

PVOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, PVOID Arguments) {
    PEXCEPTION_FRAME ExceptionList;
    PEXCEPTION_FRAME Dispatch = NULL;
    DWORD Disposition;
    DWORD Depth;
    CONTEXT Context = {0};
    EXCEPTION_RECORD Record = {
            .ExceptionCode = dwExceptionCode,
            .ExceptionFlags = dwExceptionFlags,
            .ExceptionAddress =  &&finished,
            .NumberParameters = nNumberOfArguments,
    };

    // Setup Record
    memcpy(&Record.ExceptionInformation, Arguments, nNumberOfArguments * sizeof(ULONG));

    // No need to log C++ Exceptions, this is the common case.
    if (dwExceptionCode != 0xE06D7363) {
        LogMessage("%#x, %#x, %u, %p", dwExceptionCode, dwExceptionFlags, nNumberOfArguments, Arguments);
    }

    // Fetch Exception List
    asm("mov %%fs:0, %[list]" : [list] "=r"(ExceptionList));

    DebugLog("C++ Exception %#x! ExceptionList %p, Dumping SEH Chain...", dwExceptionCode, ExceptionList);

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DWORD Result;

        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                Depth++, "",
                ExceptionList,
                ExceptionList->prev,
                ExceptionList->handler);

        Result = ExceptionList->handler(&Record, ExceptionList, &Context, &Dispatch);

        DebugLog("%*s Handler Result: %u, Dispatch: %p", Depth, "", Result, Dispatch);

        if (Result == ExceptionContinueSearch) {
            continue;
        }

        // I've never seen any other handler return code with mpengine.
        __debugbreak();
    }

    // Unhandled Exception?
    DebugLog("%u Element SEH Chain Complete.", Depth);

    finished:
    // I've never seen this reached, I'm not sure if it works.
    __debugbreak();
    return NULL;
}

#endif

DECLARE_CRT_EXPORT("RaiseException", RaiseException);

#ifdef __x86_64__
DECLARE_CRT_EXPORT("RtlUnwindEx", RtlUnwindEx);
DECLARE_CRT_EXPORT("RtlPcToFileHeader", RtlPcToFileHeader);
#else
DECLARE_CRT_EXPORT("RtlUnwind", RtlUnwind);
#endif
