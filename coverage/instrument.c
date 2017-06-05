#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#include "xed-interface.h"
#include "tree.h"

#if defined(TARGET_IA32) && defined(TARGET_LINUX) && !defined(PIN_FAST_ANALYSIS_CALL)
# define PIN_FAST_ANALYSIS_CALL __attribute__((regparm(3)))
#else
# define PIN_FAST_ANALYSIS_CALL
#endif

static tree_t *blocks;

typedef struct {
    uintptr_t address;      // Address of block
    size_t    size;         // Size of block
    uint32_t  count;        // Number of times I've been here
} execution_record_t;

VOID PIN_FAST_ANALYSIS_CALL instrument_basic_block(ADDRINT address, UINT32 size)
{
    static execution_record_t zero, *hblock = &zero;
    void **data;

    execution_record_t *record, block = {
        .address = address,
        .size    = size,
        .count   = 0,
    };

    void __attribute__((constructor)) init()
    {
        int __attribute__ ((pure)) compare(const void *a, const void *b)
        {
            const execution_record_t *x = a, *y = b;
            return x->address - y->address;
        }

        tree_create(&blocks, compare, free);
    }

    // Is this a call to my hottest block?
    if (hblock->address == address) {
        hblock->count++;
        return;
    }

    // No luck, do a slow btree lookup...
    if (tree_find(blocks, &block, &data)) {
        record = *data;
    } else {
        // Create a new record to install
        record = malloc(sizeof(execution_record_t));
        memcpy(record, &block, sizeof(execution_record_t));
        tree_add(blocks, record, &data);
    }

    // Is this entry now hot?
    if (record->count++ >= hblock->count) {
        hblock = record;
    }

    return;
}

static const char kCoverageReport[] = "coverage.txt";
static const char kCoverageVariable[] = "COVERAGE_REPORT_FILE";

VOID instrument_fini_callback(INT32 code, VOID *v)
{
    unsigned instructions = 0;
    unsigned blockcount = 0;
    unsigned totalinstructions = 0;
    unsigned totalblocks = 0;
    const execution_record_t *hblock = NULL;
    FILE *output  = fopen(getenv(kCoverageVariable)
                            ? getenv(kCoverageVariable)
                            : kCoverageReport, "wx");

    void calculate_block_stats(const void *v) {
        const execution_record_t *d = v;
        blockcount++;
        instructions += d->size;
        totalblocks += d->count;
        totalinstructions += d->size * d->count;

        if (hblock == NULL || hblock->count < d->count)
            hblock = d;
    }

    void print_basic_blocks(const void *v) {
        register uintptr_t address = ((const execution_record_t *)(v))->address;
        fprintf(output, "%#010" PRIxPTR "\n", address);
    }

    if (output != NULL) {
        tree_walk(blocks, print_basic_blocks);
    }

    tree_walk(blocks, calculate_block_stats);

    fprintf(stderr, "\n\n----- COVERAGE ANALYSIS -----\n");
    fprintf(stderr, "\t%10u Unique Instructions Executed\n", instructions);
    fprintf(stderr, "\t%10u Unique Basic Blocks Executed\n", blockcount);
    fprintf(stderr, "\t%10u Total Instructions Executed\n", totalinstructions);
    fprintf(stderr, "\t%10u Total Basic Blocks Executed\n", totalblocks);

    if (hblock) {
        fprintf(stderr, "\tHottest Basic Block (%#018" PRIxPTR ")\n", hblock->address);
        fprintf(stderr, "\t\t%10u Executes\n", hblock->count);
        fprintf(stderr, "\t\t%10u Instructions\n", hblock->size);
    }

    tree_destroy(blocks);

    if (output) {
        fclose(output);
    }

    return;
}
