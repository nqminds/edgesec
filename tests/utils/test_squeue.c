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
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils/log.h"
#include "utils/squeue.h"

static void test_init_string_queue(void **state)
{
  (void) state; /* unused */

  struct string_queue* sq = init_string_queue(-1);
  assert_int_equal(sq->max_length, -1);
  free_string_queue(sq);
}

static void test_free_string_queue(void **state)
{
  (void) state; /* unused */

  struct string_queue* sq = init_string_queue(-1);

  free_string_queue(sq);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_init_string_queue),
    cmocka_unit_test(test_free_string_queue)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
