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
#include <cmocka.h>

#include "utils/log.h"

static void test_capture_opt2config(void **state)
{
  (void) state; /* unused */
}

static void test_capture_config2opt(void **state)
{
  (void) state; /* unused */
}

int main(int argc, char *argv[])
{  
  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_capture_opt2config),
    cmocka_unit_test(test_capture_config2opt)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
