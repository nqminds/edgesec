#define _GNU_SOURCE

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include <utarray.h>

static void test_utarray(void **state) {
  (void)state; /* unused */

  UT_array *strs;
  /* Testing utarray string insert */

  utarray_new(strs, &ut_str_icd);
  char *str = "one";
  utarray_push_back(strs, &str);
  str = "two";
  utarray_push_back(strs, &str);
  str = "three";
  utarray_push_back(strs, &str);

  char **p = NULL;
  p = (char **)utarray_next(strs, p);
  assert_string_equal(*p, "one");

  p = (char **)utarray_next(strs, p);
  assert_string_equal(*p, "two");

  p = (char **)utarray_next(strs, p);
  assert_string_equal(*p, "three");

  utarray_free(strs);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_utarray)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
