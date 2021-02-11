#ifndef __MYHOOKS_H
#define __MYHOOKS_H


extern struct hsearch_data winapihooks;

#define ADD_CUSTOM_HOOK(_name, _dst)                                        \
    static void __attribute__((constructor(102))) __const__ ## _dst (void)  \
    {                                                                       \
        if (winapihooks.table == NULL)                                      \
            hcreate_r(1024, &winapihooks);                                  \
        ENTRY api_e = { _name, NULL }, *api_ep;                             \
        hsearch_r(api_e, FIND, &api_ep, &crtexports);                       \
        if (api_ep == NULL)                                                 \
            return;                                                         \
        subhook_t *hook = (subhook_t *) calloc(1, sizeof(subhook_t));       \
        *hook = subhook_new(api_ep->data, _dst, 0);                         \
        subhook_install(*hook);                                             \
        ENTRY e = { _name, hook }, *ep;                                     \
        hsearch_r(e, ENTER, &ep, &winapihooks);                             \
        return;                                                             \
    }

void EnableHook(char *name);

void DisableHook(char *name);

#else
# warn winapihooks.h included twice
#endif
