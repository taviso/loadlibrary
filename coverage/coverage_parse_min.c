#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// This utility will try to parse coverage logs of the form <block>:<input> and
// output a minimal set cover.
//
// The algorithm works like this:
//
//  Parse all of the input into a hashtable, such that T[H(input)] is a linked
//  list of blocks that it touches. The input can be in any order, we will
//  always handle it correctly (sorting very large input first is too slow).
//  This is just so we can find out which input handles which blocks.
//
//  Create an array of all the inputs we've seen, then sort it by size of the
//  block list.
//
// Unpack the array into a balanced binary tree, such that lookup(block) ==
// input, overwriting each node with the new address.
//
//
// So we effectively end up with:
//
//      [0 input1]      [0 input2]
//      [1 input1]      [1 input1]
//      [2 input1]  ->  [2 input1]
//      [3 input1]      [3 input1]
//      [4 input1]      [4 input1]
//                      [5 input2]
//
//  etc, etc, until we have an approximate minimal set of inputs.
//
// gcc -std=gnu99 -O2 $(pkg-config glib-2.0 --cflags) $(pkg-config glib-2.0 --libs) -o coverage_parse_min coverage_parse_min.c  $(pkg-config glib-2.0 --libs)
//
//
// Input is expected to be bbaddress:filename, example:
//
//  0x123123:file1.txt
//  0x232323:file2.txt
//
// Tavis Ormandy.

typedef struct {
    gchar  *input;
    GArray *blocks;
} coverage_t;

static gint block_size_compare(gconstpointer a, gconstpointer b)
{
    coverage_t * const *x = a, * const *y = b;

    return (*x)->blocks->len - (*y)->blocks->len;
}

static gint address_compare(gconstpointer a, gconstpointer b, gpointer user)
{
    return GPOINTER_TO_SIZE(a) - GPOINTER_TO_SIZE(b);
}

static gboolean dump_minimised_tree(gpointer key, gpointer value, gpointer data)
{
    g_print("%#010x:%s", GPOINTER_TO_SIZE(key), value);
    return false;
}

static void free_coverage_data(gpointer data)
{
    coverage_t *d = data;
    g_array_free(d->blocks, true);
    g_free(d->input);
    g_free(d);
}

int main(int argc, char **argv)
{
    guint        lines      = 0;
    gchar       *lineptr    = NULL;
    gsize        linelen    = 0;
    GHashTable  *index      = g_hash_table_new(g_str_hash, g_str_equal);
    GPtrArray   *coverage   = g_ptr_array_new_with_free_func(free_coverage_data);
    GTree       *tree       = g_tree_new_full(address_compare,
                                              NULL,
                                              NULL,
                                              NULL);

    while (getline(&lineptr, &linelen, stdin) != -1) {
        gchar       **input = g_strsplit(lineptr, ":", 2);
        gchar      *endchar = NULL;
        guintptr      value = g_ascii_strtoull(input[0], &endchar, 16);
        coverage_t   *data  = g_hash_table_lookup(index, input[1]);

        // Check it parsed okay.
        if (value == 0 || *endchar != '\0') {
            g_warning("dropped illegal record line %s", lineptr);
            g_strfreev(input);
            continue;
        }

        // Search for input[1] in the coverage array by checking if we have it
        // in the hash table.
        if (data == NULL) {
            // Not found, so add this input to the array.
            data            = g_new0(coverage_t, 1);
            data->input     = g_strdup(input[1]);
            data->blocks    = g_array_new(false, true, sizeof(guintptr));

            // And add this block we've just seen.
            g_array_append_val(data->blocks, value);

            // Record this new input.
            g_ptr_array_add(coverage, data);

            // And index it for fast lookup
            g_hash_table_insert(index, input[1], data);
        } else {
            // Match found, this input already has a record, just add the
            // block to it's array and continue.
            g_array_append_val(data->blocks, value);
        }

        // Clear the input line.
        g_strfreev(input);

        // Record lines parsed.
        lines++;
    }

    g_message("completed parsing %u unique input values in %u lines", coverage->len + 1, lines);

    // Now sort array based on blocks size.
    g_ptr_array_sort(coverage, block_size_compare);

    // Now insert into a binary tree, which replaces the associative shell
    // array I used to use, but has essentially the same effect.
    for (guint i = 0; i < coverage->len; i++) {
        coverage_t *data = g_ptr_array_index(coverage, i);

        for (guint j = 0; j < data->blocks->len; j++) {
            g_tree_replace(tree, GSIZE_TO_POINTER(g_array_index(data->blocks, guintptr, j)), data->input);
        }
    }

    // Now dump the tree.
    g_tree_foreach(tree, dump_minimised_tree, NULL);

    g_hash_table_destroy(index);
    g_ptr_array_free(coverage, true);
    g_tree_destroy(tree);
    free(lineptr);
    return 0;
}
