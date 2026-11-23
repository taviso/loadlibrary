#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"

struct hsearch_data extraexports;

int main(void)
{
    char path[] = "/tmp/loadlibrary-map-XXXXXX";
    const uintptr_t imagebase = 0x1000;
    const size_t base = 0x100;
#if defined(__x86_64__)
    const char *map = "0001:100001234 example_symbol\n";
    const uintptr_t address = UINT64_C(0x100001234);
#else
    const char *map = "0001:00001234 example_symbol\n";
    const uintptr_t address = 0x1234;
#endif
    int fd = mkstemp(path);
    if (fd < 0)
        return 1;
    if (write(fd, map, strlen(map)) != (ssize_t) strlen(map)) {
        close(fd);
        unlink(path);
        return 2;
    }
    close(fd);

    bool loaded = process_extra_exports((void *) imagebase, base, path);
    unlink(path);
    ENTRY key = { .key = "example_symbol" }, *result = NULL;
    if (!loaded || !hsearch_r(key, FIND, &result, &extraexports))
        return 3;
    return (uintptr_t) result->data != imagebase + base + address;
}
