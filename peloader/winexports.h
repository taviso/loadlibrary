#ifndef __WINEXPORTS_H
#define __WINEXPORTS_H

#include "hook.h"

extern struct hsearch_data crtexports;

#ifdef __x86_64__
#define DECLARE_CRT_EXPORT(_name, _func, _n_args)                                           \
    static void __constructor __const__ ## _func (void)                                     \
    {                                                                                       \
        ENTRY e = { _name, _func }, *ep;                                                    \
        if (crtexports.table == NULL)                                                       \
            hcreate_r(1024, &crtexports);                                                   \
        insert_function_redirect(_func, _n_args, NULL, CALLING_CONVENTION_SWITCH, WIN2NIX); \
        hsearch_r(e, ENTER, &ep, &crtexports);                                              \
        return;                                                                             \
    }
#else
#define DECLARE_CRT_EXPORT(_name, _func)                 \
    static void __constructor __const__ ## _func (void)  \
    {                                                    \
        ENTRY e = { _name, _func }, *ep;                 \
        if (crtexports.table == NULL)                    \
            hcreate_r(1024, &crtexports);                \
        hsearch_r(e, ENTER, &ep, &crtexports);           \
        return;                                          \
    }
#endif
#else
# warn winexports.h included twice
#endif
