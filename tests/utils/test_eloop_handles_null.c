#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "utils/log.h"
#include "utils/eloop.h"

#include "./wrap_log_error.h"

/**
 * List of all functions that should be tested whether they handle
 * @p eloop is @p NULL.
 *
 * This definition relies on the X macro being expanded.
 * The first time it's expanded, it creates the `test_..._handles_eloop_null`
 * function defininition.
 *
 * The second time it's expanded, it creates an array of `cmocka_unit_test()`
 * structs.
 *
 * This pattern is called [X
 * Macros](https://www.drdobbs.com/the-new-c-x-macros/184401387)
 */
#define TEST_HANDLE_ELOOP_NULL_FUNCTIONS                                       \
  X(eloop_register_read_sock, (NULL, 0, NULL, NULL, NULL))                     \
  X(eloop_register_sock, (NULL, 0, EVENT_TYPE_READ, NULL, NULL, NULL))         \
  X(eloop_register_timeout, (NULL, 0, 0, NULL, NULL, NULL))                    \
  X(eloop_cancel_timeout, (NULL, NULL, NULL, NULL))                            \
  X(eloop_cancel_timeout_one, (NULL, NULL, NULL, NULL, NULL))                  \
  X(eloop_is_timeout_registered, (NULL, NULL, NULL, NULL))                     \
  X(eloop_deplete_timeout, (NULL, 0, 0, NULL, NULL, NULL))                     \
  X(eloop_replenish_timeout, (NULL, 0, 0, NULL, NULL, NULL))

// Creates all the test functions defined in TEST_HANDLE_ELOOP_NULL_FUNCTIONS
#define X(function, args)                                                      \
  /* should return and log error on null input */                              \
  static void test_##function##_handles_eloop_null(void **state) {             \
    /** unused*/ (void)state;                                                  \
    expect_function_call(log_error);                                           \
    expect_string(__wrap_log_levels, error_message, "eloop param is NULL");    \
    assert_int_equal(function args, -1);                                       \
  }
TEST_HANDLE_ELOOP_NULL_FUNCTIONS
#undef X

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

// adds all the unit tests defined by TEST_HANDLE_ELOOP_NULL_FUNCTIONS
#define X(function, args)                                                      \
  cmocka_unit_test(test_##function##_handles_eloop_null),

  const struct CMUnitTest tests[] = {TEST_HANDLE_ELOOP_NULL_FUNCTIONS};
#undef X

  return cmocka_run_group_tests(tests, NULL, NULL);
}
