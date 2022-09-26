#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
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
// used to delete directory recursively
#include <ftw.h>

#include "utils/log.h"
#include "utils/os.h"
#include "utils/allocs.h"

static void test_copy_argv(void **state) {
  (void)state; /* unused */

  { // should return valid copy of argv
    const char *const argv[] = {"/usr/bin/env", "uname", "-s", NULL};

    char **argv_copy = copy_argv(argv);
    assert_non_null(argv_copy);

    assert_ptr_not_equal(argv, argv_copy);
    for (size_t i = 0; i < sizeof(argv) - 1; i++) {
      const char *arg = argv[0];
      char *arg_copy = argv_copy[0];

      // pointers should have the exact same bytes
      // but point to different areas in memory
      assert_non_null(arg_copy);
      assert_ptr_not_equal(arg, arg_copy);
      assert_string_equal(arg, arg_copy);

      // string pointer and string data should be very close together
      ptrdiff_t ptr_diff = (char *)arg_copy - (char *)argv_copy;
      ptrdiff_t max_ptr_diff =
          sizeof(char *) * ARRAY_SIZE(argv) + // size of string pointers
          strlen(argv[0]) + strlen(argv[1]) +
          strlen(argv[2]); // size of string buffer
      assert_in_range(ptr_diff, sizeof(char *), max_ptr_diff);
    }

    // C-compiler shouldn't throw an errors/warnings about modifying argv_copy
    argv_copy[0][0] = 'h';

    free(argv_copy);
  }

  // should return NULL if input was invalid
  assert_true(NULL == copy_argv(NULL));
}

static void command_out_fn(void *ctx, void *buf, size_t count) {
  check_expected(ctx);
  // check count first, so we don't do accidentally do malloc(-1) and get some
  // weird errors
  check_expected(count);
  // the string data in buf is probably not null terminated, so
  // we have to manually null terminate it outselves.
  char *null_terminated_str = malloc(count + 1);
  assert_non_null(null_terminated_str);
  null_terminated_str[count] = '\0';
  strncpy(null_terminated_str, buf, count);
  check_expected(null_terminated_str);
  free(null_terminated_str);
}

static void test_run_command(void **state) {
  (void)state; /* unused */

  const char *const argv[] = {"/usr/bin/env", "uname", "-s", NULL};
  // we need to make a copy of argv, since run_command might modify the data
  char **argv_copy = copy_argv(argv);
  assert_non_null(argv_copy);

  /* Testing run_command with /usr/bin/env uname -s */
  int status = run_command(argv_copy, NULL, NULL, NULL);
  assert_int_equal(status, 0);

  {
    const char *const argv1[] = {"/bin/chuppauname", "-s", NULL};
    char **argv1_copy = copy_argv(argv1);
    assert_non_null(argv1_copy);

    /* Testing run_command with /bin/chuppauname -s */
    status = run_command(argv1_copy, NULL, NULL, NULL);
    assert_int_not_equal(status, 0);

    free(argv1_copy);
  }

  /* Testing run_command with NULL */
  status = run_command(NULL, NULL, NULL, NULL);
  assert_int_not_equal(status, 0);

  char *argv2[] = {NULL};
  /* Testing run_command with {NULL} */
  status = run_command(argv2, NULL, NULL, NULL);
  assert_int_not_equal(status, 0);

  { // test process_callback_fn
    expect_string(command_out_fn, ctx, "Context");
    expect_string(command_out_fn, null_terminated_str, "Hello World!\n");
    expect_value(command_out_fn, count,
                 sizeof("Hello World!\n") - 1); // -1 due to no null terminator

    const char *hello_world_argv[] = {"/usr/bin/env", "echo", "Hello World!",
                                      NULL};
    char **hello_world_argv_copy = copy_argv(hello_world_argv);
    status =
        run_command(hello_world_argv_copy, NULL, command_out_fn, "Context");
    assert_int_equal(status, 0);
    free(hello_world_argv_copy);
  }

  free(argv_copy);
}

int fn_split_string(const char *str, size_t len, void *data) {
  UT_array *strs = (UT_array *)data;
  char *dest = (char *)os_malloc(len + 1);
  memset(dest, '\0', len + 1);
  strncpy(dest, str, len);
  utarray_push_back(strs, &dest);
  os_free(dest);

  return 0;
}

static void test_split_string(void **state) {
  (void)state; /* unused */

  char **p = NULL;
  UT_array *strs = NULL;
  size_t count;
  char *str_one = ":";

  utarray_new(strs, &ut_str_icd);
  /* Testing split_string on input: \":\" */
  count = split_string(str_one, ':', fn_split_string, strs);
  assert_int_equal(count, (size_t)2);
  p = (char **)utarray_next(strs, p);
  assert_non_null(p);
  assert_int_equal(strlen(*p), (size_t)0);
  p = (char **)utarray_next(strs, p);
  assert_non_null(p);
  assert_int_equal(strlen(*p), (size_t)0);

  utarray_free(strs);

  strs = NULL;
  utarray_new(strs, &ut_str_icd);
  char *str_two = "12345:";
  p = NULL;

  /* Testing split_string on input: \"12345\" */
  count = split_string(str_two, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t)2);

  p = (char **)utarray_next(strs, p);
  assert_string_equal(*p, "12345");

  p = (char **)utarray_next(strs, p);
  assert_int_equal(strlen(*p), (size_t)0);

  utarray_free(strs);
  strs = NULL;
  utarray_new(strs, &ut_str_icd);

  char *str_three = ":12345";
  p = NULL;

  /* Testing split_string on input: \":12345\" */
  count = split_string(str_three, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t)2);

  p = (char **)utarray_next(strs, p);
  assert_int_equal(strlen(*p), (size_t)0);

  p = (char **)utarray_next(strs, p);
  assert_string_equal(*p, "12345");

  utarray_free(strs);
  utarray_new(strs, &ut_str_icd);

  char *str_four = "12345";
  p = NULL;

  /* Testing split_string on input: \"12345\" */
  count = split_string(str_four, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t)1);

  p = (char **)utarray_next(strs, p);
  assert_string_equal(*p, "12345");

  utarray_free(strs);
  utarray_new(strs, &ut_str_icd);

  char *str_five = "";
  p = NULL;
  /* Testing split_string on input: "" */
  count = split_string(str_five, ':', fn_split_string, strs);
  assert_int_equal(count, (ssize_t)1);

  p = (char **)utarray_next(strs, p);
  assert_int_equal(strlen(*p), (ssize_t)0);

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

static void test_split_string_array(void **state) {
  (void)state; /* unused */

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);
  char *str = "12345:abcdef";

  /* Testing split_string_array on input: \"%s\" */

  size_t count = split_string_array(str, ':', arr);
  assert_int_equal(count, 2);

  char **p = NULL;
  p = (char **)utarray_next(arr, p);
  assert_string_equal(*p, "12345");

  p = (char **)utarray_next(arr, p);
  assert_string_equal(*p, "abcdef");

  count = split_string_array(str, ':', NULL);
  assert_int_equal(count * (-1), 1);

  utarray_free(arr);
}

static void test_allocate_string(void **state) {
  (void)state; /* unused */

  /* Testing allocate_string on 1234567890qwerty */
  char *test = os_strdup("1234567890qwerty");

  assert_string_equal(test, "1234567890qwerty");

  free(test);
}

static void test_concat_paths(void **state) {
  (void)state; /* unused */

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

static void test_get_valid_path(void **state) {
  (void)state; /* unused */

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

static void test_construct_path(void **state) {
  (void)state; /* unused */

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

static void test_get_secure_path(void **state) {
  (void)state; /* unused */

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);
  char *bin_path = "/bin";
  utarray_push_back(arr, &bin_path);

  /* Testing get_secure_path on path /bin and binary ls */
  char *path = get_secure_path(arr, "ls", NULL);
  bool comp =
      (strcmp(path, "/bin/ls") == 0) || (strcmp(path, "/usr/bin/ls") == 0);

  assert_true(comp);

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

bool check_if_bin_ls(char *dirpath, void *args) {
  bool *found_ls = args;
  if (strcmp(dirpath, "/bin/ls") == 0) {
    *found_ls = true;
  }

  return true;
}

bool failing_dir_fn(char *dirpath, void *args) {
  (void)dirpath;
  (void)args;
  return false;
}

static void test_list_dir(void **state) {
  (void)state;

  bool found_ls = false;
  assert_return_code(list_dir("/bin", check_if_bin_ls, &found_ls), errno);
  assert_true(found_ls);

  // should fail for invalid folder
  assert_int_equal(
      list_dir("/this-path-is-not-a-dir", check_if_bin_ls, &found_ls), -1);

  // should fail if dir_fn fails
  assert_int_equal(list_dir("/bin", failing_dir_fn, &found_ls), -1);
}

typedef struct {
  char tmp_dir[256];
} make_dirs_to_path_t;

static int test_make_dirs_to_path_setup(void **state) {
  make_dirs_to_path_t *test_state = test_calloc(1, sizeof(make_dirs_to_path_t));
  *state = test_state;

  // ignore return value if directory creation failed
  mkdir("/tmp/edgesec_tests", 0755);
  char template[] = "/tmp/edgesec_tests/os_tests.XXXXXX";
  char *tmp_dir = mkdtemp(template);

  // check to see if tmp_dir was built correctly
  assert_non_null(tmp_dir);

  strcpy(test_state->tmp_dir, tmp_dir);
  return 0;
}

// recursively delete folder using ftw
static int rm_file(const char *pathname, const struct stat *sbuf, int type,
                   struct FTW *ftwb) {
  (void)sbuf;
  (void)type;
  (void)ftwb;

  if (remove(pathname) < 0) {
    perror("ERROR: remove");
    return -1;
  }
  return 0;
}
static int rm_dir_recursive(const char *directory) {
  int ret_val = nftw(directory, rm_file, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
  if (ret_val) {
    printf("Error when trying to delete '%s'", directory);
    perror("ERROR: rm_dir_recursive for directory");
  }
  return ret_val;
}

static int test_make_dirs_to_path_teardown(void **state) {
  make_dirs_to_path_t *test_state = *state;
  if (test_state == NULL) {
    return 0;
  }

  assert_string_not_equal(test_state->tmp_dir, "");
  int ret_val = rm_dir_recursive(test_state->tmp_dir);
  assert_int_equal(ret_val, 0);
  strcpy(test_state->tmp_dir, "");

  test_free(*state);
  *state = NULL;
  return 0;
}

static void test_make_dirs_to_path(void **state) {
  make_dirs_to_path_t *test_state = *state;
  char *directories_to_build =
      construct_path(test_state->tmp_dir, "should/create/these/dirs");
  char *path = construct_path(directories_to_build, "not_a_dir.txt");

  int ret = make_dirs_to_path(path, 0755);
  // should return no error code
  assert_int_equal(ret, 0);

  struct stat file_stats;
  int file_exists = check_file_exists(path, &file_stats);
  // should not exist
  assert_int_equal(file_exists, -1);
  assert_int_equal(errno, ENOENT);

  // directories should exist
  int dir_exists = exist_dir(directories_to_build);
  assert_int_equal(dir_exists, 1); // true if dir exists

  // should return no error when directories already exist
  ret = make_dirs_to_path(path, 0755);
  // should return no error code
  assert_int_equal(ret, 0);

  // should return an error on invalid input string
  ret = make_dirs_to_path(NULL, 0755);
  assert_int_equal(ret, -1);

  // create a file in the directory
  FILE *fp = fopen(path, "w");
  assert_non_null(fp);
  assert_int_not_equal(fputs("test file, should be deleted", fp), EOF);
  assert_int_not_equal(fclose(fp), EOF);

  // should throw a ENOTDIR (NOT A DIRECTORY) error when trying to create
  // folder in `not_a_dir.txt`
  char *enotdir_path = construct_path(directories_to_build,
                                      "not_a_dir.txt/new_folder/new_file.txt");
  assert_int_equal(make_dirs_to_path(enotdir_path, 0755), -1);
  free(enotdir_path);

  free(directories_to_build);
  free(path);
}

static void test_string_append_char(void **state) {
  (void)state; /* unused */
  const char input_str[] = "Hello World";
  char *combined_str = string_append_char(input_str, '!');
  assert_string_equal(combined_str, "Hello World!");

  // should return NULL if input str is NULL
  assert_ptr_equal(string_append_char(NULL, '!'), NULL);

  free(combined_str);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_copy_argv),
      cmocka_unit_test(test_run_command),
      cmocka_unit_test(test_split_string),
      cmocka_unit_test(test_split_string_array),
      cmocka_unit_test(test_allocate_string),
      cmocka_unit_test(test_concat_paths),
      cmocka_unit_test(test_get_valid_path),
      cmocka_unit_test(test_construct_path),
      cmocka_unit_test(test_get_secure_path),
      cmocka_unit_test(test_list_dir),
      cmocka_unit_test(test_string_append_char),
      cmocka_unit_test_setup_teardown(test_make_dirs_to_path,
                                      test_make_dirs_to_path_setup,
                                      test_make_dirs_to_path_teardown)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
