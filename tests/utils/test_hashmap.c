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
#include "utils/hashmap.h"

static void test_hashmap_str_keychar(void **state) {
  (void)state; /* unused */

  hmap_str_keychar *hmap = NULL;

  /* Inserting value value1 for key key1 */
  hmap_str_keychar_put(&hmap, "key1", "value1");
  char *value = hmap_str_keychar_get(&hmap, "key1");
  assert_string_equal(value, "value1");

  /* Inserting value value2 for key NULL */
  hmap_str_keychar_put(&hmap, NULL, "value2");
  value = hmap_str_keychar_get(&hmap, NULL);
  assert_null(value);

  /* Inserting value value3 for key \"\" */
  hmap_str_keychar_put(&hmap, "", "value3");
  value = hmap_str_keychar_get(&hmap, "");
  assert_string_equal(value, "value3");

  /* Inserting value value4 for key \"\" */
  hmap_str_keychar_put(&hmap, "", "value4");
  value = hmap_str_keychar_get(&hmap, "");
  assert_string_equal(value, "value4");

  /* Inserting value NULL for key key3 */
  hmap_str_keychar_put(&hmap, "key3", NULL);
  value = hmap_str_keychar_get(&hmap, "key3");
  assert_null(value);

  /* Inserting value value3 for key 1234567890qwerty */
  hmap_str_keychar_put(&hmap, "1234567890qwerty", "value3");
  value = hmap_str_keychar_get(&hmap, "1234567890qwerty");
  assert_string_equal(value, "value3");

  /* Inserting value value3 for key 1234567890qwerty123456789 */
  hmap_str_keychar_put(&hmap, "1234567890qwerty123456789", "value3");
  value = hmap_str_keychar_get(&hmap, "1234567890qwerty123456789");
  assert_null(value);

  hmap_str_keychar_free(&hmap);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_hashmap_str_keychar)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
