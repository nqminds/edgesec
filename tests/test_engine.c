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
  struct app_config app_config = {0, .quarantine_vlanid = -1, .default_open_vlanid = -1};

  // Load the bin paths array
  const char * paths[] = {
    "/bin", "/usr/bin", "/usr/sbin"
  };
  utarray_new(app_config.bin_path_array, &ut_str_icd);
  for (size_t idx = 0; idx < sizeof(paths) / sizeof(paths[0]); idx++) {
    utarray_push_back(app_config.bin_path_array, &(paths[idx]));
  }

  int context_error = init_context(&app_config, &context);
  // TODO: currently init_context test fails
  assert_int_not_equal(context_error, 0);

  if (context_error == 0) { // automatically frees on error
    utarray_free(app_config.bin_path_array);
  }
  free_bridge_list(context.bridge_list);
  free_sqlite_macconn_db(context.macconn_db);

}

int main(int argc, char *argv[])
{
  (void) argc;
  (void) argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_init_context)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
