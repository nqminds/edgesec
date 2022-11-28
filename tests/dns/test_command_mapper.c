#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>

#include "dns/command_mapper.h"
#include "utils/log.h"
#include "utils/os.h"

static void test_put_command_mapper(void **state) {
  (void)state;

  hmap_command_conn *hmap = NULL;
  char *command = "test";

  assert_int_equal(put_command_mapper(&hmap, command), 0);

  free_command_mapper(&hmap);
}

static void test_check_command_mapper(void **state) {
  (void)state;

  hmap_command_conn *hmap = NULL;
  char *command1 = "test1";
  char *command2 = "test2";

  put_command_mapper(&hmap, command1);
  assert_int_equal(check_command_mapper(&hmap, command1), 1);
  assert_int_equal(check_command_mapper(&hmap, command2), 0);

  free_command_mapper(&hmap);
}

int main(int argc, char *argv[]) {
  (void)argc; /* unused */
  (void)argv; /* unused */

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_put_command_mapper),
      cmocka_unit_test(test_check_command_mapper)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
