#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "./utils/log.h"

#include "./config.h"
#include <libgen.h>
#include <limits.h>

static void get_edgesec_root_dir(char buffer[static PATH_MAX]) {
  char this_file[] = __FILE__;
  const char *edgesec_root_dir = dirname(dirname(this_file));
  strncpy(buffer, edgesec_root_dir, PATH_MAX - 1);
  buffer[PATH_MAX - 1] = '\0';
}

static void test_load_config(const char *path_to_config_from_root_dir) {
  struct app_config config = {0};

  char edgesec_root_dir[PATH_MAX];
  get_edgesec_root_dir(edgesec_root_dir);

  // need to make copy since construct_path() uses non-const char*
  char path_to_config[PATH_MAX] = {0};
  strncpy(path_to_config, path_to_config_from_root_dir, PATH_MAX - 1);

  char *full_config_path = construct_path(edgesec_root_dir, path_to_config);
  log_debug("Loading app config from %s", full_config_path);
  bool ret = load_app_config(full_config_path, &config);
  assert_true(ret);

  free(full_config_path);
  free_app_config(&config);
}

static void test_load_configs(void **state) {
  (void)state; /* unused */
  test_load_config("dev-config.ini");
  test_load_config("deployment/owrt-config/config-dev.ini");
  test_load_config("deployment/owrt-config/config.ini");
  test_load_config("deployment/rpi-config/config.ini");
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
