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

#include "system_checks.h"
#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/utarray.h"
#include "utils/iw.h"

static void test_check_systems_commands(void **state) {
  (void)state; /* unused */

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);
  char *bin_path = "/bin";
  utarray_push_back(arr, &bin_path);
  char *commands[] = {"ls", NULL};

  /* Testing check_systems_commands with ls command on /bin */
  hmap_str_keychar *hmap = check_systems_commands(commands, arr, NULL);

  assert_non_null(hmap);

  char *value = hmap_str_keychar_get(&hmap, "ls");

  assert_string_equal(value, "/bin/ls");

  hmap_str_keychar_free(&hmap);

  /* Testing check_systems_commands with lschuppa command on /bin */
  char *commands1[] = {"lschuppa", NULL};
  hmap = check_systems_commands(commands1, arr, NULL);

  assert_null(hmap);
  hmap_str_keychar_free(&hmap);

  /* Testing check_systems_commands with empty command on /bin */
  char *commands2[] = {NULL};
  hmap = check_systems_commands(commands2, arr, NULL);

  assert_null(hmap);

  hmap_str_keychar_free(&hmap);

  /* Testing check_systems_commands with NULL command on /bin */
  hmap = check_systems_commands(NULL, arr, NULL);

  assert_null(hmap);

  hmap_str_keychar_free(&hmap);

  utarray_free(arr);
  utarray_new(arr, &ut_str_icd);

  /* Testing check_systems_commands with ls command on empty path array */
  hmap = check_systems_commands(commands, arr, NULL);

  assert_null(hmap);

  hmap_str_keychar_free(&hmap);

  /* Testing check_systems_commands with ls command on NULL path array */
  hmap = check_systems_commands(commands, NULL, NULL);

  assert_null(hmap);

  hmap_str_keychar_free(&hmap);
  utarray_free(arr);
}

int main(int argc, char *argv[]) {
  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_check_systems_commands)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
