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

static execution_record_t zero, *hblock = &zero;

static int compare_execution_record(const void *a, const void *b)
{
    const execution_record_t *x = a, *y = b;
    return (x->address > y->address) - (x->address < y->address);
}

static void __attribute__((constructor)) init_blocks(void)
{
    tree_create(&blocks, compare_execution_record, free);
}

void PIN_FAST_ANALYSIS_CALL instrument_basic_block(uintptr_t address, uint32_t size)
{
    void **data;

    execution_record_t *record, block = {
        .address = address,
        .size    = size,
        .count   = 0,
    };

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

typedef struct {
    unsigned instructions;
    unsigned blockcount;
    unsigned totalinstructions;
    unsigned totalblocks;
    const execution_record_t *hblock;
} coverage_stats_t;

static void calculate_block_stats(const void *v, void *context)
{
    const execution_record_t *d = v;
    coverage_stats_t *stats = context;

    stats->blockcount++;
    stats->instructions += d->size;
    stats->totalblocks += d->count;
    stats->totalinstructions += d->size * d->count;

    if (stats->hblock == NULL || stats->hblock->count < d->count)
        stats->hblock = d;
}

static void print_basic_blocks(const void *v, void *context)
{
    const execution_record_t *record = v;
    FILE *output = context;
    fprintf(output, "%#010" PRIxPTR "\n", record->address);
}

void instrument_fini_callback(int32_t code, void *v)
{
    coverage_stats_t stats = {0};
    FILE *output  = fopen(getenv(kCoverageVariable)
                            ? getenv(kCoverageVariable)
                            : kCoverageReport, "wx");

    if (output != NULL) {
        tree_walk(blocks, print_basic_blocks, output);
    }

    tree_walk(blocks, calculate_block_stats, &stats);

    fprintf(stderr, "\n\n----- COVERAGE ANALYSIS -----\n");
    fprintf(stderr, "\t%10u Unique Instructions Executed\n", stats.instructions);
    fprintf(stderr, "\t%10u Unique Basic Blocks Executed\n", stats.blockcount);
    fprintf(stderr, "\t%10u Total Instructions Executed\n", stats.totalinstructions);
    fprintf(stderr, "\t%10u Total Basic Blocks Executed\n", stats.totalblocks);

    if (stats.hblock) {
        fprintf(stderr, "\tHottest Basic Block (%#018" PRIxPTR ")\n", stats.hblock->address);
        fprintf(stderr, "\t\t%10u Executes\n", stats.hblock->count);
        fprintf(stderr, "\t\t%10zu Instructions\n", stats.hblock->size);
    }

    tree_destroy(blocks);

    if (output) {
        fclose(output);
    }

    return;
}
