#ifndef __MYHOOKS_H
#define __MYHOOKS_H

#include "subhook.h"


extern struct hsearch_data my_hooks;

#define ADD_CUSTOM_HOOK(_name, _src, _dst)                               \
    static void __constructor __const__ ## _src (void)                   \
    {                                                                    \
        if (my_hooks.table == NULL)                                      \
            hcreate_r(1024, &my_hooks);                                  \
        subhook_t *hook = (subhook_t *) calloc(1, sizeof(subhook_t));    \
        *hook = subhook_new(_src, _dst, 0);                              \
        subhook_install(*hook);                                          \
        ENTRY e = { _name, hook }, *ep;                                  \
        hsearch_r(e, ENTER, &ep, &my_hooks);                             \
        return;                                                          \
    }

void EnableHook(char *name);

void DisableHook(char *name);

#else
# warn my_hooks.h included twice
#endif
