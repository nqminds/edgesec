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
#include "utils/os.h"
#include "utils/utarray.h"

static void command_out_fn(void *ctx, void *buf, size_t count)
{
  if (strncmp("Linux\n", buf, count) != 0 ) {
    fail();
  }
}

static void test_run_command(void **state)
{
  (void) state; /* unused */

  char *argv[3] = {"/bin/uname", "-s", NULL};

  /* Testing run_command with /bin/uname -s */
  int status = run_command(argv, NULL, NULL, NULL);
  assert_int_equal(status, 0);

  char *argv1[3] = {"/bin/chuppauname", "-s", NULL};

  /* Testing run_command with /bin/chuppauname -s */
  status = run_command(argv1, NULL, NULL, NULL);
  assert_int_not_equal(status, 0);

  /* Testing run_command with NULL */
  status = run_command(NULL, NULL, NULL, NULL);
  assert_int_not_equal(status, 0);

  char *argv2[1] = {NULL};
  /* Testing run_command with {NULL} */
  status = run_command(argv2, NULL, NULL, NULL);
  assert_int_not_equal(status, 0);

  /* Testing run_command with /bin/uname -s and callback */
  status = run_command(argv, NULL, command_out_fn, NULL);
  assert_int_equal(status, 0);
}

void fn_split_string(const char *str, size_t len, void *data)
{
  UT_array *strs = (UT_array *)data;
  char *dest = (char *)malloc(len + 1);
  memset(dest, '\0', len + 1);
  strncpy(dest, str, len);
  utarray_push_back(strs, &dest);
  free(dest);
}

static void test_split_string(void **state)
{
  (void) state; /* unused */

  UT_array *strs;
  char *str_one = ":";

  utarray_new(strs,&ut_str_icd);

  /* Testing split_string on input: \":\" */
  size_t count = split_string(str_one, ':', fn_split_string, strs);
  assert_int_equal(count, (size_t) 2);

  char **p = NULL;
  p = (char**)utarray_next(strs, p);
  assert_int_equal(strlen(*p), (size_t) 0);

  p = (char**)utarray_next(strs, p);
  assert_int_equal(strlen(*p), (size_t) 0);

  utarray_free(strs);
  utarray_new(strs,&ut_str_icd);
  char *str_two = "12345:";
  p = NULL;

  /* Testing split_string on input: \"12345\" */
  count = split_string(str_two, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t) 2);

  p = (char**)utarray_next(strs,p);
  assert_string_equal(*p, "12345");

  p = (char**)utarray_next(strs, p);
  assert_int_equal(strlen(*p), (size_t) 0);

  utarray_free(strs);
  utarray_new(strs,&ut_str_icd);

  char *str_three = ":12345";
  p = NULL;

  /* Testing split_string on input: \":12345\" */
  count = split_string(str_three, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t) 2);

  p = (char**)utarray_next(strs, p);
  assert_int_equal(strlen(*p), (size_t) 0);

  p = (char**)utarray_next(strs, p);
  assert_string_equal(*p, "12345");

  utarray_free(strs);
  utarray_new(strs,&ut_str_icd);

  char *str_four = "12345";
  p = NULL;
  
  /* Testing split_string on input: \"12345\" */
  count = split_string(str_four, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t) 1);

  p = (char**)utarray_next(strs, p);
  assert_string_equal(*p, "12345");

  utarray_free(strs);
  utarray_new(strs,&ut_str_icd);

  char *str_five = "";
  p = NULL;
  /* Testing split_string on input: "" */
  count = split_string(str_five, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t) 1);

  p = (char**)utarray_next(strs,p);
  assert_int_equal(strlen(*p), (ssize_t) 0);

  utarray_free(strs);
  utarray_new(strs, &ut_str_icd);

  /* Testing split_string on fn_split_string=NULL */
  count = split_string(str_two, ':', NULL, strs);
  assert_int_equal(count * (-1), 1);

  utarray_free(strs);
  utarray_new(strs, &ut_str_icd);

  /* Testing split_string in input string NULL */
  count = split_string(NULL, ':', fn_split_string, strs);
  assert_int_equal(count * (-1), 1);

  utarray_free(strs);
}

static void test_split_string_array(void **state)
{
  (void) state; /* unused */

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);
  char *str = "12345:abcdef";

  /* Testing split_string_array on input: \"%s\" */

  size_t count = split_string_array(str, ':', arr);
  assert_int_equal(count, 2);

  char **p = NULL;
  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "12345");

  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "abcdef");

  count = split_string_array(str, ':', NULL);
  assert_int_equal(count * (-1), 1);

  utarray_free(arr);
}

static void test_allocate_string(void **state)
{
  (void) state; /* unused */

  /* Testing allocate_string on 1234567890qwerty */
  char *test = os_strdup("1234567890qwerty");

  assert_string_equal(test, "1234567890qwerty");

  free(test);
}

static void test_concat_paths(void **state)
{
  (void) state; /* unused */

  char *path_left_one = "./";
  char *path_right_one = "./";

  char *concat = concat_paths(path_left_one, path_right_one);

  /* Testing concat_path function on ./ ./ */
  assert_string_equal(concat, ".//./");

  free(concat);

  concat = concat_paths(NULL, path_right_one);
  /* Testing concat_path function on NULL ./ */
  assert_string_equal(concat, "./");

  free(concat);

  concat = concat_paths(path_left_one, NULL);
  /* Testing concat_path function on ./ NULL */
  assert_string_equal(concat, "./");

  free(concat);

  concat = concat_paths(NULL, NULL);
  /* Testing concat_path function on NULL NULL */
  assert_string_equal(concat, "");

  free(concat);
}

static void test_get_valid_path(void **state)
{
  (void) state; /* unused */

  char *path = NULL;

  path = get_valid_path("systemd-machine-id-setup");
  assert_non_null(path);
  assert_string_equal(path, "./systemd-machine-id-setup");
  free(path);

  /* Testing get_valid_path function on /test/// */
  path = get_valid_path("/test///");
  assert_string_equal(path, "/test");

  free(path);

  /* Testing get_valid_path function on ./test/ */

  path = get_valid_path("./test/");
  assert_string_equal(path, "./test");

  free(path);

  /* Testing get_valid_path function on /./test/ */

  path = get_valid_path("/./test/");
  assert_string_equal(path, "/./test");

  free(path);

  /* Testing get_valid_path function on /../test/ */;

  path = get_valid_path("/../test/");
  assert_string_equal(path, "/../test");

  free(path);

  /* Testing get_valid_path function on test/./ */

  path = get_valid_path("test/./");
  assert_string_equal(path, "test/.");

  free(path);

  /* Testing get_valid_path function on ////test///bin// */

  path = get_valid_path("////test///bin//");
  assert_string_equal(path, "////test/bin");

  free(path);

  /* Testing get_valid_path function on NULL */

  path = get_valid_path(NULL);
  assert_null(path);

  free(path);

  /* Testing get_valid_path function on "" */

  path = get_valid_path("");
  assert_string_equal(path, ".");

  free(path);

  /* Testing get_valid_path function on "." */

  path = get_valid_path(".");
  assert_string_equal(path, ".");

  free(path);

  /* Testing get_valid_path function on \"..\" */

  path = get_valid_path("..");
  assert_string_equal(path, "..");

  free(path);

  /* Testing get_valid_path function on "./../" */

  path = get_valid_path("./../");
  assert_string_equal(path, "./..");

  free(path);

  /* Testing get_valid_path function on "/" */

  path = get_valid_path("/");
  assert_string_equal(path, "/");

  free(path);
}

static void test_construct_path(void **state)
{
  (void) state; /* unused */

  /* Testing construct_path function on / and / */

  char *path = construct_path("/", "/");
  assert_string_equal(path, "//");

  free(path);

  /* Testing construct_path function on / and // */

  path = construct_path("/", "//");
  assert_string_equal(path, "//");

  free(path);

  /* Testing construct_path function on /bin and .test */

  path = construct_path("/bin", ".test");
  assert_string_equal(path, "/bin/.test");

  free(path);

  /* Testing construct_path function on /bin and ./test */

  path = construct_path("/bin", "./test");
  assert_string_equal(path, "/bin/test");

  free(path);

  /* Testing construct_path function on ./bin and ./test */

  path = construct_path("./bin", "./test");
  assert_string_equal(path, "./bin/test");

  free(path);

  /* Testing construct_path function on ./bin and ./test */

  path = construct_path("./bin", "./test");
  assert_string_equal(path, "./bin/test");

  free(path);

  /* Testing construct_path function on ./bin/ and "" */

  path = construct_path("./bin/", "");
  assert_string_equal(path, "./bin");

  free(path);

  /* Testing construct_path function on "" and ./bin/ */

  path = construct_path("", "./bin/");
  assert_string_equal(path, "./bin");

  free(path);

  /* Testing construct_path function on "" and "" */

  path = construct_path("", "");
  assert_string_equal(path, ".");

  free(path);

  /* Testing construct_path function on NULL and /bin */

  path = construct_path(NULL, "/bin");
  assert_null(path);

  free(path);

  /* Testing construct_path function on NULL and NULL */

  path = construct_path(NULL, NULL);
  assert_null(path);

  free(path);

  /* Testing construct_path function on ./bin/ and NULL */

  path = construct_path("./bin/", NULL);
  assert_null(path);

  free(path);

  /* Testing construct_path function on /bin/ and /test/ */

  path = construct_path("/bin/", "/test/");
  assert_string_equal(path, "/bin/test");

  free(path);
}

static void test_get_secure_path(void **state)
{
  (void) state; /* unused */

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);
  char *bin_path = "/bin";
  utarray_push_back(arr, &bin_path);

  /* Testing get_secure_path on path /bin and binary ls */
  char *path = get_secure_path(arr, "ls", NULL);
  assert_string_equal(path, "/bin/ls");

  free(path);

  /* Testing get_secure_path on path /bin and binary lschuppa */
  path = get_secure_path(arr, "lschuppa", NULL);
  assert_null(path);

  free(path);

  /* Testing get_secure_path on input array NULL */
  path = get_secure_path(NULL, "ls", NULL);
  assert_null(path);

  free(path);

  /* Testing get_secure_path on input filename NULL */
  path = get_secure_path(arr, NULL, NULL);
  assert_null(path);

  free(path);
  utarray_free(arr);
}

bool dir_fn(char *dirpath, void *args)
{
  int *is_uname = args;
  if (strcmp(dirpath, "/bin/uname") == 0) {
    *is_uname = 1;
  }

  return true;
}

static void test_list_dir(void **state)
{
  int is_uname = 0;
  int ret = list_dir("/bin", dir_fn, &is_uname);
  assert_int_equal(ret, 0);
  assert_int_equal(is_uname, 1);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_run_command),
    cmocka_unit_test(test_split_string),
    cmocka_unit_test(test_split_string_array),
    cmocka_unit_test(test_allocate_string),
    cmocka_unit_test(test_concat_paths),
    cmocka_unit_test(test_get_valid_path),
    cmocka_unit_test(test_construct_path),
    cmocka_unit_test(test_get_secure_path),
    cmocka_unit_test(test_list_dir),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
