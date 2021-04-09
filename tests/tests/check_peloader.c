#include <check.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "winnt_types.h"
#include "pe_linker.h"

// tests for x86_64 peloader library
// Author: Alessandro De Vito (cube0x8)

Suite *s;
TCase *tc;


START_TEST(test_check_nt_hdr) {
    struct pe_image pe = {
            .entry  = NULL,
            .name = "./data/mpengine.dll",
    };

    pe_load_library(pe.name, &pe.image, &pe.size);

    pe.nt_hdr = (PIMAGE_NT_HEADERS) (pe.image + 0xF8);

    int result = check_nt_hdr(pe.nt_hdr);

    pe_unload_library(pe);

    ck_assert_int_eq(result, IMAGE_FILE_EXECUTABLE_IMAGE);
}

END_TEST

START_TEST(test_link_pe_images) {
    struct pe_image pe = {
            .entry  = NULL,
            .name = "./data/mpengine.dll",
    };

    pe_load_library(pe.name, &pe.image, &pe.size);

    pe.nt_hdr = (PIMAGE_NT_HEADERS) (pe.image + 0xF8);
    pe.opt_hdr = (PIMAGE_OPTIONAL_HEADER) (pe.image + 0x110);

    int result = link_pe_images(&pe, 1);

    pe_unload_library(pe);

    ck_assert_int_eq(result, 0);
}

END_TEST

Suite *peloader_suite(void) {
    TCase *tc_core;

    s = suite_create("peloader");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_check_nt_hdr);
    tcase_add_test(tc_core, test_link_pe_images);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed = 0;
    SRunner *runner;

    runner = srunner_create(peloader_suite());
    srunner_set_fork_status(runner, CK_NOFORK);
    srunner_run_all(runner, CK_NORMAL);

    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}