#ifndef __WINEXPORTS_H
#define __WINEXPORTS_H

extern struct hsearch_data crtexports;

#define DECLARE_CRT_EXPORT(_name, _func)                    \
    static void __constructor __const__ ## _func (void)     \
    {                                                       \
        ENTRY e = { _name, _func }, *ep;                    \
        if (crtexports.table == NULL)                       \
            hcreate_r(1024, &crtexports);                   \
        hsearch_r(e, ENTER, &ep, &crtexports);              \
        return;                                             \
    }

#else
# warn winexports.h included twice
#endif
