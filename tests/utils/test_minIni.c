#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <fcntl.h>
#include <inttypes.h>
#include <minIni.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils/log.h"

static const char *tmp_file = "/tmp/test_iniXXXXXX";

static int setup(void **state) {
  char *filename = malloc(strlen(tmp_file) + 1);
  strcpy(filename, tmp_file);

  int fd = mkostemp(filename, O_APPEND);

  if (fd == -1) {
    perror("mkostemp");
    return -1;
  }

  FILE *fp = fdopen(fd, "a+");

  if (fp == NULL) {
    perror("fopen error");
    return -1;
  }

  fprintf(fp, "# last modified 1 April 2001 by John Doe\n");
  fprintf(fp, "[owner]\n");
  fprintf(fp, "name = John Doe\n");
  fprintf(fp, "organization = Acme Widgets Inc.\n");
  fprintf(fp, "\n");
  fprintf(fp, "[database]\n");
  fprintf(fp,
          "# use IP address in case network name resolution is not working\n");
  fprintf(fp, "server=192.0.2.62\n");
  fprintf(fp, "port = 143\n");
  fprintf(fp, "file=\"payroll.dat\"\n");
  fprintf(fp, "float=0.123456\n");

  rewind(fp);
  fclose(fp);

  *state = filename;
  return 0;
}

static int teardown(void **state) {
  FILE *fp = fopen(*state, "rb");
  if (fp == NULL) {
    perror("fopen error");
    return -1;
  }
  unlink(tmp_file);
  fclose(fp);
  free(*state);

  return 0;
}

static void test_ini_one(void **state) {
  (void)state; /* unused */

  char *value = malloc(INI_BUFFERSIZE);
  ini_gets("owner", "name", "", value, INI_BUFFERSIZE, *state);
  assert_string_equal(value, "John Doe");
  free(value);

  value = malloc(INI_BUFFERSIZE);
  ini_gets("owner", "organization", "", value, INI_BUFFERSIZE, *state);
  assert_string_equal(value, "Acme Widgets Inc.");
  free(value);

  value = malloc(INI_BUFFERSIZE);
  ini_gets("owner", "unknown", "", value, INI_BUFFERSIZE, *state);
  assert_string_equal(value, "");
  free(value);

  value = malloc(INI_BUFFERSIZE);
  ini_gets("database", "server", "", value, INI_BUFFERSIZE, *state);
  assert_string_equal(value, "192.0.2.62");
  free(value);

  int port = ini_getl("database", "port", 0, *state);
  assert_int_equal(port, 143);

  value = malloc(INI_BUFFERSIZE);
  ini_gets("database", "file", "", value, INI_BUFFERSIZE, *state);
  assert_string_equal(value, "payroll.dat");
  free(value);

  float fvalue = ini_getf("database", "float", 0.0, *state);
  assert_float_equal(fvalue, 0.123456f, 0.000001f);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_ini_one, setup, teardown)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
