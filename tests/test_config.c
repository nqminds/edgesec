#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "./utils/log.h"

#include "./config.h"
#include <libgen.h>
#include <limits.h>

static void test_load_configs(void **state) {
  (void)state; /* unused */

  struct app_config config = {0};

  int ret = load_app_config(TEST_CONFIG_INI_PATH, &config);
  assert_int_equal(ret, 0);

  free_app_config(&config);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_load_configs),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
