#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "runctl.h"
#include "config.h"

/**
 * @brief Performs an integration test on edgesec
 */
static void test_edgesec(void **state) {
  (void)state; /* unused */

  log_trace("%s", TEST_CONFIG_INI_PATH);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_edgesec)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
