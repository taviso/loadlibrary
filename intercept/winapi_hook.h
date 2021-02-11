#ifndef __MYHOOKS_H
#define __MYHOOKS_H


extern struct hsearch_data winapihooks;

#define ADD_CUSTOM_HOOK(_name, _src, _dst)                               \
    static void __constructor __const__ ## _src (void)                   \
    {                                                                    \
        if (winapihooks.table == NULL)                                      \
            hcreate_r(1024, &winapihooks);                                  \
        subhook_t *hook = (subhook_t *) calloc(1, sizeof(subhook_t));    \
        *hook = subhook_new(_src, _dst, 0);                              \
        subhook_install(*hook);                                          \
        ENTRY e = { _name, hook }, *ep;                                  \
        hsearch_r(e, ENTER, &ep, &winapihooks);                             \
        return;                                                          \
    }

void EnableHook(char *name);

void DisableHook(char *name);

#else
# warn winapihooks.h included twice
#endif
