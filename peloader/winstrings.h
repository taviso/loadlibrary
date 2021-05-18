#ifndef __STRINGS_H
#define __STRINGS_H

size_t CountWideChars(const void *wcharbuf);
char * CreateAnsiFromWide(void *wcharbuf);
char *string_from_wchar(void *wcharbuf, size_t len);

#define wcscmp _win_wcscmp
#define wcsicmp _win_wcsicmp
extern INT wcscmp(const wchar_t *s1, const wchar_t *s2);
extern INT wcsicmp(const wchar_t *s1, const wchar_t *s2);

#endif
