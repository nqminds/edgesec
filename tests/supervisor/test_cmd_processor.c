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

#include "supervisor/cmd_processor.h"

#include "utils/hashmap.h"
#include "utils/utarray.h"
#include "utils/log.h"

static void test_process_domain_buffer(void **state)
{
  (void) state; /* unused */  

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);

  char buf1[5] = {'c', CMD_DELIMITER, 'a', CMD_DELIMITER, 'b'};

  bool ret = process_domain_buffer(buf1, 5, arr);

  assert_true(ret);

  char **p = NULL;
  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "c");
  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "a");
  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "b");

  p = (char**)utarray_next(arr, p);
  assert_ptr_equal(p, NULL);

  utarray_free(arr);

  utarray_new(arr, &ut_str_icd);
  char buf2[4] = {'P', 'I', 'N', 'G'};
  ret = process_domain_buffer(buf2, 4, arr);

  assert_true(ret);

  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "PING");

  utarray_free(arr);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_process_domain_buffer)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
