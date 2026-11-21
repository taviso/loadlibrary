
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <search.h>

#include "tree.h"

// Create a new tree with the specified compare routine
bool tree_create(tree_t **tree, int (*compare)(const void *a, const void *b), void (*free)(void *))
{
    assert(compare);
    assert(tree);

    if ((*tree = malloc(sizeof(tree_t)))) {
        (*tree)->root = NULL;
        (*tree)->compare = compare;
        (*tree)->free = free;
        return true;
    }

    return false;
}

typedef struct {
    void (*function)(const void *, void *);
    void *context;
} tree_walk_context_t;

static tree_walk_context_t current_walk;

static void tree_walk_action(const void *nodep, VISIT which, int depth)
{
    const void * const *data = nodep;

    switch (which) {
        case postorder:
        case leaf:
            current_walk.function(*data, current_walk.context);
            break;
        case preorder:
        case endorder:
            break;
        default:
            assert(false);
            break;
    }
}

// Execute function for every node of the tree.
bool tree_walk(tree_t *tree, void (*function)(const void *, void *), void *context)
{
    assert(function);
    assert(tree);
    current_walk = (tree_walk_context_t) { function, context };
    twalk(tree->root, tree_walk_action);
    return true;
}

// Add new data item to the tree, set node to either data or an
// existing node such that tree->compare(data, node) returns zero.
bool tree_add(tree_t *tree, const void *data, void ***node)
{
    assert(tree);
    assert(data);
    assert(node);
    return !! (*node = tsearch(data, &tree->root, tree->compare));
}

// As tree_add, but dont add the item in data.
bool tree_find(tree_t *tree, const void *data, void ***node)
{
    assert(tree);
    assert(data);
    assert(node);
    return !! (*node = tfind(data, &tree->root, tree->compare));
}

// Clear up a tree.
bool tree_destroy(tree_t *tree)
{
    tdestroy(tree->root, tree->free);
    free(tree);
    return true;
}
