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

#include "supervisor/sqlite_macconn_writer.h"
#include "system/system_checks.h"
#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/utarray.h"

#include "supervisor/supervisor_config.h"
#include "engine.h"

static void test_init_context(void **state)
{
  (void) state; /* unused */
  struct supervisor_context context;
  struct app_config app_config;
  memset(&app_config, 0, sizeof(struct app_config));
  assert_true(init_context(&app_config, &context));
  free_bridge_list(context.bridge_list);
  free_sqlite_macconn_db(context.macconn_db);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_init_context)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
