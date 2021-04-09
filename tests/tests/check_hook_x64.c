#include <check.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include "subhook.h"
#include "hook.h"
#include "winnt_types.h"
#include "pe_linker.h"

// tests for x86_64 hook library
// Author: Alessandro De Vito (cube0x8)

Suite *s;
TCase *tc;

int redirect(int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8) {
    if (arg1 != 1)
        goto error;
    if (arg2 != 2)
        goto error;
    if (arg3 != 3)
        goto error;
    if (arg4 != 4)
        goto error;
    if (arg5 != 5)
        goto error;
    if (arg6 != 6)
        goto error;
    if (arg7 != 7)
        goto error;
    if (arg8 != 8)
        goto error;
    return 0x1337;

    error:
    return -1;
}

START_TEST(test_insert_function_redirect_nix_2_win) {
    struct pe_image pe = {
            .entry  = NULL,
            .name = "./data/testdll.dll",
    };

    int (*test_sum)(int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8);

    pe_load_library(pe.name, &pe.image, &pe.size);

    pe.nt_hdr = (PIMAGE_NT_HEADERS) (pe.image + 0x100);
    pe.opt_hdr = (PIMAGE_OPTIONAL_HEADER) (pe.image + 0x118);

    // Handle relocations, imports, etc.
    link_pe_images(&pe, 1);

    get_export("test_sum", &test_sum);

    insert_function_redirect(test_sum, NULL, CALLING_CONVENTION_SWITCH, NIX2WIN);

    int result = test_sum(1, 2, 3, 4, 5, 6, 7, 8);

    pe_unload_library(pe);

    ck_assert_int_eq(result, 36);
}

END_TEST

START_TEST(test_insert_function_redirect_win_2_nix) {
    struct pe_image pe = {
            .entry  = NULL,
            .name = "./data/testdll.dll",
    };

    int (*call_test_sum)();
    int (*test_sum)(int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8);

    pe_load_library(pe.name, &pe.image, &pe.size);

    pe.nt_hdr = (PIMAGE_NT_HEADERS) (pe.image + 0x100);
    pe.opt_hdr = (PIMAGE_OPTIONAL_HEADER) (pe.image + 0x118);

    // Handle relocations, imports, etc.
    link_pe_images(&pe, 1);

    get_export("call_test_sum", &call_test_sum);
    get_export("test_sum", &test_sum);

    insert_function_redirect(test_sum, redirect, HOOK_REPLACE_FUNCTION, WIN2NIX);
    insert_function_redirect(call_test_sum, NULL, CALLING_CONVENTION_SWITCH, NIX2WIN);

    int result = call_test_sum();

    pe_unload_library(pe);

    ck_assert_int_eq(result, 0x1337);
}

END_TEST

START_TEST(test_remove_function_redirect) {
    struct pe_image pe = {
            .entry  = NULL,
            .name = "./data/testdll.dll",
    };

    int (*call_test_sum)();
    int (*test_sum)(int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8);

    pe_load_library(pe.name, &pe.image, &pe.size);

    pe.nt_hdr = (PIMAGE_NT_HEADERS) (pe.image + 0x100);
    pe.opt_hdr = (PIMAGE_OPTIONAL_HEADER) (pe.image + 0x118);

    // Handle relocations, imports, etc.
    link_pe_images(&pe, 1);

    get_export("call_test_sum", &call_test_sum);
    get_export("test_sum", &test_sum);

    P_REDIRECT function_redirect = insert_function_redirect(test_sum, redirect, HOOK_REPLACE_FUNCTION, WIN2NIX);
    insert_function_redirect(call_test_sum, NULL, CALLING_CONVENTION_SWITCH, NIX2WIN);

    int hooked_result = call_test_sum();

    int remove_result = remove_function_redirect(function_redirect);

    insert_function_redirect(test_sum, NULL, CALLING_CONVENTION_SWITCH, NIX2WIN);
    int original_result = test_sum(1, 2, 3, 4, 5, 6, 7, 8);

    pe_unload_library(pe);

    ck_assert_int_eq(hooked_result, 0x1337);
    ck_assert_int_eq(remove_result, true);
    ck_assert_int_eq(original_result, 0x24);
}

END_TEST

Suite *hook_suite(void) {
    TCase *tc_core;

    s = suite_create("hook");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_insert_function_redirect_nix_2_win);
    tcase_add_test(tc_core, test_insert_function_redirect_win_2_nix);
    tcase_add_test(tc_core, test_remove_function_redirect);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    SRunner *sr;

    sr = srunner_create(hook_suite());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_VERBOSE);

    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}