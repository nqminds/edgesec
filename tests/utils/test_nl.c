#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils/nl.h"

struct nl_test_state_t {
  struct nlctx *context; // default nlctx test context
};

const char *test_nl_interface_name = "test_nl_interface_name";
// reserved testing IP https://datatracker.ietf.org/doc/html/rfc5737
const char *test_nl_interface_ip = "192.0.2.1";
const char *test_nl_interface_broadcast_ip = "192.0.2.255";
const char *test_nl_subnet_mask = "24";

static int setup(void **state) {
  struct nl_test_state_t *ptr = malloc(sizeof(struct nl_test_state_t));
  if (ptr == NULL) {
    return -1;
  }
  ptr->context = nl_init_context();
  if (ptr->context == NULL) {
    return -1;
  }
  *state = ptr;
  return 0;
}

static int teardown(void **state) {
  struct nl_test_state_t *ptr = *state;
  nl_free_context(ptr->context);
  free(ptr);
  return 0;
}

static void test_nl_set_interface_ip(void **state) {
  struct nl_test_state_t *ptr = *state;

  // checks that nl_set_interface_ip fails if the interface doesn't exist yet
  expect_function_call(log_error);
  expect_string(
      __wrap_log_levels, error_message,
      "ipaddr_modify error: could not find interface 'test_nl_interface_name'");
  expect_function_call(log_error);
  expect_string(__wrap_log_levels, error_message,
                "nl_set_interface_ip error: ipaddr_modify failed with -1");
  assert_int_equal(nl_set_interface_ip(ptr->context, test_nl_interface_name,
                                       test_nl_interface_ip,
                                       test_nl_interface_broadcast_ip,
                                       test_nl_subnet_mask),
                   -1);

  // unused currently
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_nl_set_interface_ip),
  };

  return cmocka_run_group_tests(tests, setup, teardown);
}
