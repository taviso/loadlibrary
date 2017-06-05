
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

// Execute function for every node of the tree
bool tree_walk(tree_t *tree, void (*function)(const void *))
{
    assert(function);
    assert(tree);

    void action(const void *nodep, const VISIT which, const int depth)
    {
        const void * const * data = nodep;
        switch (which) {
            case postorder:
            case leaf:
                function(*data);
                break;
            case preorder:
            case endorder:
                break;
            default:
                assert(false);
                break;
        }
        return;
    }

    twalk(tree->root, action);
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
