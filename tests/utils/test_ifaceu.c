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
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils/log.h"
#include "utils/ifaceu.h"

static void test_iface_exists(void **state) {
  (void)state; /* unused */

  /* Testing iface_exists for lo */
  bool ret = iface_exists("lo");
  assert_true(ret);

  /* Testing iface_exists for chuppa123 */
  ret = iface_exists("chuppa123");
  assert_false(ret);

  /* Testing iface_exists for NULL */
  ret = iface_exists(NULL);
  assert_false(ret);

  /* Testing iface_exists for "" */
  ret = iface_exists("");
  assert_false(ret);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_iface_exists)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
