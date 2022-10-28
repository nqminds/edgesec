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
#include <stdint.h>
#include <cmocka.h>
#include <pthread.h>

#include "runctl.h"
#include "config.h"

pthread_mutex_t log_lock;

void log_lock_fun(bool lock) {
  if (lock) {
    pthread_mutex_lock(&log_lock);
  } else {
    pthread_mutex_unlock(&log_lock);
  }
}

/**
 * @brief Performs an integration test on edgesec
 */
static void test_edgesec(void **state) {
  (void)state; /* unused */

  struct app_config config;

  // Init the app config struct
  memset(&config, 0, sizeof(struct app_config));

  assert_int_equal(load_app_config(TEST_CONFIG_INI_PATH, &config), 0);

  os_init_random_seed();
  run_ctl(&config);

  free_app_config(&config);
  pthread_mutex_destroy(&log_lock);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);
  log_set_lock(log_lock_fun);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_edgesec)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
