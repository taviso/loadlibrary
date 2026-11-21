#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "hook.h"

typedef int (__attribute__((ms_abi)) *test_function)(int);
static test_function original;
static int hits;

static int __attribute__((ms_abi)) wrapper(int value)
{
    ++hits;
    return original(value) * 2;
}

static int __attribute__((ms_abi)) replacement(int value)
{
    ++hits;
    return value + 100;
}

static void __attribute__((ms_abi)) observe(void)
{
    ++hits;
}

int main(void)
{
    /* The second instruction crosses the five-byte detour boundary. */
    const unsigned char code[] = {
        0x89, 0xc8,                         /* mov eax, ecx */
        0x81, 0xc0, 0x01, 0x00, 0x00, 0x00, /* add eax, 1 */
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xc3                                /* ret */
    };
    const unsigned char rip_relative[] = {
        0x8b, 0x05, 0x1a, 0x00, 0x00, 0x00, 0xc3
    };
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    subhook_t hook;
    test_function function;

    if (page == MAP_FAILED)
        return 1;
    memcpy(page, code, sizeof code);
    function = (test_function) page;
    if (function(3) != 4)
        return 2;

    hook = insert_function_wrapper(page, wrapper, (void **) &original);
    if (!hook || function(3) != 8 || hits != 1)
        return 3;
    if (!remove_function_redirect(hook) || memcmp(page, code, sizeof code))
        return 4;

    hits = 0;
    hook = insert_function_redirect(page, observe, HOOK_DEFAULT);
    if (!hook || function(3) != 4 || hits != 1)
        return 5;
    if (!remove_function_redirect(hook) || memcmp(page, code, sizeof code))
        return 6;

    hits = 0;
    hook = insert_function_redirect(page, replacement, HOOK_REPLACE_FUNCTION);
    if (!hook || function(3) != 103 || hits != 1)
        return 7;
    if (!remove_function_redirect(hook) || memcmp(page, code, sizeof code))
        return 8;

    memcpy(page, rip_relative, sizeof rip_relative);
    *(uint32_t *) ((unsigned char *) page + 32) = 42;
    hits = 0;
    hook = insert_function_wrapper(page, wrapper, (void **) &original);
    if (hook) {
        if (function(3) != 84 || hits != 1 || !remove_function_redirect(hook))
            return 9;
    } else if (original != NULL) {
        return 10;
    }
    if (memcmp(page, rip_relative, sizeof rip_relative) || function(3) != 42)
        return 10;

    if (insert_function_redirect(page, observe, HOOK_DEFAULT) != NULL)
        return 11;

    munmap(page, 4096);
    puts("x64 hook checks passed");
    return 0;
}
