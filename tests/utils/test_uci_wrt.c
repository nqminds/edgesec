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
#include "utils/uci_wrt.h"
#include "utils/utarray.h"

static void test_uwrt_init_context(void **state)
{
  (void) state;

  struct uctx *context = uwrt_init_context(NULL);
  assert_non_null(context);
  uwrt_free_context(context);
#ifdef TEST_UCI_CONFIG_DIR
  context = uwrt_init_context(TEST_UCI_CONFIG_DIR);
  assert_non_null(context);
  uwrt_free_context(context);
#endif
}

#ifdef TEST_UCI_CONFIG_DIR
static void test_uwrt_get_interfaces(void **state)
{
  struct uctx *context = uwrt_init_context(TEST_UCI_CONFIG_DIR);
  uwrt_get_interfaces(context, 0);
  uwrt_free_context(context);
}
#endif

int main(int argc, char *argv[])
{  
  (void) argc;
  (void) argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_uwrt_init_context),
#ifdef TEST_UCI_CONFIG_DIR
    cmocka_unit_test(test_uwrt_get_interfaces),
#endif
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
