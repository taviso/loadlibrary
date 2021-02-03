#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "my_hooks.h"


struct hsearch_data my_hooks;


void EnableHook(char *name)
{
    ENTRY e = { name, NULL }, *ep;
    hsearch_r(e, FIND, &ep, &my_hooks);

    subhook_install(*((subhook_t *)ep->data));
}

void DisableHook(char *name)
{
    ENTRY e = { name, NULL }, *ep;
    hsearch_r(e, FIND, &ep, &my_hooks);

    subhook_remove(*((subhook_t *)ep->data));
}
