#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "subhook.h"
#include "winapi_hook.h"


struct hsearch_data winapihooks;


void EnableHook(char *name)
{
    ENTRY e = { name, NULL }, *ep;
    hsearch_r(e, FIND, &ep, &winapihooks);

    subhook_install(*((subhook_t *)ep->data));
}

void DisableHook(char *name)
{
    ENTRY e = { name, NULL }, *ep;
    hsearch_r(e, FIND, &ep, &winapihooks);

    subhook_remove(*((subhook_t *)ep->data));
}
