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

#include "utils/log.h"
#include "capture/capture_service.h"

char *out_opt_str = "./ -i wlan0 -f port 80 -m -t 100 -n 1000 -y ndpi -e -u -w -q ./test -x SET_FINGERPRINT -z 32 -p ./db -r -1,-1 -b 100 ";

void capture_config(struct capture_conf *config)
{
  os_memset(config, 0, sizeof(struct capture_conf));

  strcpy(config->capture_bin_path, "./");
  strcpy(config->domain_server_path, "./test");
  strcpy(config->domain_command, "SET_FINGERPRINT");
  config->domain_delim = 0x20;
  strcpy(config->capture_interface, "wlan0");
  config->promiscuous = true;
  config->immediate = true;
  config->buffer_timeout = 100;
  config->process_interval = 1000;
  strcpy(config->analyser, "ndpi");
  config->file_write = true;
  config->db_write = true;
  strcpy(config->db_path, "./db");
  strcpy(config->filter, "port 80");
  config->sync_store_size = -1;
  config->sync_send_size = -1;
  config->capture_store_size = 100; 
}

static void test_capture_opt2config(void **state)
{
  (void) state; /* unused */

  struct capture_conf in, out;
  capture_config(&out);
  os_memset(&in, 0, sizeof(struct capture_conf));
  strcpy(in.capture_bin_path, "./");
  assert_int_equal(capture_opt2config('i', "wlan0", &in), 0);
  assert_int_equal(capture_opt2config('f', "port 80", &in), 0);
  assert_int_equal(capture_opt2config('m', NULL, &in), 0);
  assert_int_equal(capture_opt2config('t', "100", &in), 0);
  assert_int_equal(capture_opt2config('n', "1000", &in), 0);
  assert_int_equal(capture_opt2config('y', "ndpi", &in), 0);
  assert_int_equal(capture_opt2config('e', NULL, &in), 0);
  assert_int_equal(capture_opt2config('u', NULL, &in), 0);
  assert_int_equal(capture_opt2config('w', NULL, &in), 0);
  assert_int_equal(capture_opt2config('q', "./test", &in), 0);
  assert_int_equal(capture_opt2config('x', "SET_FINGERPRINT", &in), 0);
  assert_int_equal(capture_opt2config('z', "32", &in), 0);
  assert_int_equal(capture_opt2config('p', "./db", &in), 0);
  assert_int_equal(capture_opt2config('r', "-1,-1", &in), 0);
  assert_int_equal(capture_opt2config('b', "100", &in), 0);
  assert_int_equal(os_memcmp(&in, &out, sizeof(struct capture_conf)), 0);

  assert_int_equal(capture_opt2config('r', "-1,", &in), -1);
  assert_int_equal(capture_opt2config('r', "-1", &in), -1);
  assert_int_equal(capture_opt2config('r', "", &in), -1);
  assert_int_equal(capture_opt2config('r', ",1", &in), -1);
  assert_int_equal(capture_opt2config('r', "1,a", &in), -1);
}

static void test_capture_config2opt(void **state)
{
  (void) state; /* unused */

  struct capture_conf config;
  capture_config(&config);

  char **opt_str = capture_config2opt(&config);

  assert_non_null(opt_str);
  char *out = string_array2string(opt_str);
  assert_int_equal(strcmp(out, out_opt_str), 0);
  capture_freeopt(opt_str);
  os_free(out);
}

int main(int argc, char *argv[])
{  
  (void) argc;
  (void) argv;
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_capture_opt2config),
    cmocka_unit_test(test_capture_config2opt)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
