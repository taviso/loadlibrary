#include <check.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "../winnt_types.h"
#include "../pe_linker.h"

Suite *s;
TCase *tc;
SRunner *runner;

struct pe_image pe = {
        .entry  = NULL,
        .name = "mpengine.dll",
};

START_TEST(test_check_nt_hdr)
    {
        int result = check_nt_hdr(pe.nt_hdr);
        ck_assert_int_eq(result, IMAGE_FILE_EXECUTABLE_IMAGE);
    }END_TEST

START_TEST(test_link_pe_images)
    {
        int result = link_pe_images(&pe, 1);
        ck_assert_int_eq(result, 0);
    }END_TEST

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
    int no_failed = 0;

    if (pe_load_library(pe.name, &pe.image, &pe.size) == false) {
        return 1;
    }

    pe.nt_hdr    = (PIMAGE_NT_HEADERS)(pe.image + 0xF8);
    pe.opt_hdr   = (PIMAGE_DOS_HEADER)(pe.image + 0x110);


    s = peloader_suite();
    runner = srunner_create(s);

    //srunner_set_fork_status(runner, CK_NOFORK);
    srunner_run_all(runner, CK_NORMAL);
    no_failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}