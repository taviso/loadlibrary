#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>

#include "pin.H"

extern "C" {
    #include "xed-interface.h"
    #include "instrument.h"
    #include "tree.h"
}

static uintptr_t blacklist[] = {
    #include "blacklist.h"
};


static int compare_block_address(const void *a, const void *b)
{
    uintptr_t x =  (uintptr_t  ) a;
    uintptr_t y = *(uintptr_t *) b;

    if (x > y) return +1;
    if (x < y) return -1;

    return 0;
}

ADDRINT TraceImageStart;
ADDRINT TraceImageSize;

VOID SetImageParameters(ADDRINT ImageStart, ADDRINT ImageSize)
{
    TraceImageStart = ImageStart;
    TraceImageSize = ImageSize;
}

// Pin calls this function every time a new basic block is encountered
VOID trace(TRACE trace, VOID *ptr)
{
    if (!TraceImageStart)
        return;

    // Visit every basic block  in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        if (BBL_Address(bbl) < TraceImageStart || BBL_Address(bbl) > TraceImageStart + TraceImageSize)
            continue;

        // Check if this block is in our blacklist...
        if (bsearch((const void *)(BBL_Address(bbl) - TraceImageStart),
                    blacklist,
                    sizeof blacklist / sizeof blacklist[0],
                    sizeof blacklist[0],
                    compare_block_address)) {
            continue;
        }

        // Insert a call in every bbl, passing the address of the basic block
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(instrument_basic_block),
            IARG_FAST_ANALYSIS_CALL,
            IARG_ADDRINT, BBL_Address(bbl) - TraceImageStart,
            IARG_UINT32, BBL_NumIns(bbl),
            IARG_END);
        }
}

VOID loadimage(IMG img, VOID *ptr)
{
    RTN Callback = RTN_FindByName(img, "InstrumentationCallback");

    if (RTN_Valid(Callback)) {
        RTN_Open(Callback);
        RTN_InsertCall(Callback, IPOINT_BEFORE, (AFUNPTR) SetImageParameters,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_END);
        RTN_Close(Callback);
    }
}

int main(int argc, char **argv)
{
    // Initialize pin
    PIN_Init(argc, argv);

    // Initialize Symbols
    PIN_InitSymbols();

    // Monitor Image loads
    IMG_AddInstrumentFunction(loadimage, NULL);

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(trace, NULL);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(instrument_fini_callback, NULL);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

