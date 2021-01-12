#ifndef __STRINGS_H
#define __STRINGS_H

size_t CountWideChars(const void *wcharbuf);
char * CreateAnsiFromWide(void *wcharbuf);
char *string_from_wchar(void *wcharbuf, size_t len);

#endif
