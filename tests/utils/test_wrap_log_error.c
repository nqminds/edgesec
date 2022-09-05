#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "./wrap_log_error.h"
#include "utils/log.h"

static void test_wrap_log_levels(void **state) {
  (void)state; /* unused */

  expect_function_call(log_error);
  expect_string(__wrap_log_levels, error_message, "edgesec is great");
  log_error("edgesec is great");

  expect_function_call(log_error);
  expect_not_string(__wrap_log_levels, error_message, "edgesec is great");
  log_error("Testing testing 123");

  log_info("This should not call log_error");

  expect_function_call(log_error);
  expect_string(__wrap_log_levels, error_message, "Testing testing 456");
  log_error("Testing %s %d", "testing", 456);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_wrap_log_levels),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
