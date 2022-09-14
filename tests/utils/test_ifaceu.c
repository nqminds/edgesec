#include <stdbool.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "utils/log.h"
#include "utils/ifaceu.h"

#ifdef __FreeBSD__
static const char LOCALHOST_INTERFACE[] = "lo0";
#else
static const char LOCALHOST_INTERFACE[] = "lo";
#endif

static void test_iface_exists(void **state) {
  (void)state; /* unused */

  /* Testing iface_exists for lo */
  log_debug("Checking whether interface %s exists", LOCALHOST_INTERFACE);
  bool ret = iface_exists(LOCALHOST_INTERFACE);
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
