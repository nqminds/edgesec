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

#include "utils/allocs.h"
#include "utils/log.h"
#include "utils/squeue.h"

static void test_init_string_queue(void **state) {
  (void)state; /* unused */

  struct string_queue *sq = init_string_queue(-1);
  assert_int_equal(sq->max_length, -1);
  free_string_queue(sq);
}

static void test_free_string_queue(void **state) {
  (void)state; /* unused */

  struct string_queue *sq = init_string_queue(-1);

  free_string_queue(sq);
}

static void test_push_string_queue(void **state) {
  (void)state; /* unused */

  struct string_queue *sq = init_string_queue(-1);
  assert_int_equal(push_string_queue(sq, NULL), -1);
  assert_int_equal(get_string_queue_length(sq), 0);

  assert_int_equal(push_string_queue(sq, ""), 0);
  assert_int_equal(get_string_queue_length(sq), 1);

  assert_int_equal(push_string_queue(sq, "test"), 0);
  assert_int_equal(get_string_queue_length(sq), 2);

  free_string_queue(sq);

  sq = init_string_queue(0);
  push_string_queue(sq, "test1");
  assert_int_equal(get_string_queue_length(sq), 0);

  push_string_queue(sq, "test2");
  assert_int_equal(get_string_queue_length(sq), 0);
  free_string_queue(sq);

  sq = init_string_queue(1);
  push_string_queue(sq, "test1");
  assert_int_equal(get_string_queue_length(sq), 1);
  push_string_queue(sq, "test2");
  assert_int_equal(get_string_queue_length(sq), 1);
  push_string_queue(sq, "test3");
  assert_int_equal(get_string_queue_length(sq), 1);
  free_string_queue(sq);

  sq = init_string_queue(2);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  assert_int_equal(get_string_queue_length(sq), 2);
  free_string_queue(sq);

  sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  assert_int_equal(get_string_queue_length(sq), 3);
  free_string_queue(sq);
}

static void test_pop_string_queue(void **state) {
  (void)state; /* unused */
  char *str = NULL;

  struct string_queue *sq = init_string_queue(-1);
  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_null(str);
  free_string_queue(sq);

  sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");

  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_string_equal(str, "test1");
  os_free(str);

  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_string_equal(str, "test2");
  os_free(str);

  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_string_equal(str, "test3");
  os_free(str);

  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_null(str);
  free_string_queue(sq);

  sq = init_string_queue(0);
  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_null(str);
  free_string_queue(sq);

  sq = init_string_queue(0);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");

  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_null(str);
  free_string_queue(sq);

  sq = init_string_queue(1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");

  assert_int_equal(pop_string_queue(sq, &str), 0);
  assert_string_equal(str, "test3");
  os_free(str);
  free_string_queue(sq);
}

static void test_empty_string_queue(void **state) {
  (void)state; /* unused */
  char *str = NULL;
  struct string_queue *sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  empty_string_queue(sq, -1);
  assert_int_equal(get_string_queue_length(sq), 0);
  free_string_queue(sq);

  sq = init_string_queue(0);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  empty_string_queue(sq, -1);
  assert_int_equal(get_string_queue_length(sq), 0);
  free_string_queue(sq);

  sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  empty_string_queue(sq, 0);
  assert_int_equal(get_string_queue_length(sq), 3);
  free_string_queue(sq);

  sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  empty_string_queue(sq, 1);
  assert_int_equal(get_string_queue_length(sq), 2);

  peek_string_queue(sq, &str);
  assert_string_equal(str, "test2");
  os_free(str);

  empty_string_queue(sq, 1);
  assert_int_equal(get_string_queue_length(sq), 1);
  pop_string_queue(sq, &str);
  assert_string_equal(str, "test3");
  os_free(str);

  free_string_queue(sq);

  sq = init_string_queue(2);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");

  empty_string_queue(sq, 4);
  assert_int_equal(get_string_queue_length(sq), 0);
  free_string_queue(sq);

  sq = init_string_queue(4);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  push_string_queue(sq, "test4");

  empty_string_queue(sq, 2);
  assert_int_equal(get_string_queue_length(sq), 2);

  pop_string_queue(sq, &str);
  assert_string_equal(str, "test3");
  os_free(str);

  pop_string_queue(sq, &str);
  assert_string_equal(str, "test4");
  os_free(str);

  free_string_queue(sq);
}

static void test_peep_string_queue(void **state) {
  (void)state; /* unused */
  char *str = NULL;
  struct string_queue *sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  push_string_queue(sq, "test4");

  peek_string_queue(sq, &str);
  assert_string_equal(str, "test1");
  os_free(str);

  free_string_queue(sq);
}

static void test_concat_string_queue(void **state) {
  (void)state; /* unused */
  char *str;

  struct string_queue *sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  push_string_queue(sq, "test4");

  str = concat_string_queue(sq, -1);
  assert_string_equal(str, "test1test2test3test4");
  os_free(str);
  free_string_queue(sq);

  sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  push_string_queue(sq, "test4");

  str = concat_string_queue(sq, 1);
  assert_string_equal(str, "test1");
  os_free(str);
  free_string_queue(sq);

  sq = init_string_queue(-1);
  push_string_queue(sq, "test1");
  push_string_queue(sq, "test2");
  push_string_queue(sq, "test3");
  push_string_queue(sq, "test4");

  str = concat_string_queue(sq, 0);
  assert_null(str);
  free_string_queue(sq);
}

int main(int argc, char *argv[]) {
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_string_queue),
      cmocka_unit_test(test_free_string_queue),
      cmocka_unit_test(test_push_string_queue),
      cmocka_unit_test(test_pop_string_queue),
      cmocka_unit_test(test_empty_string_queue),
      cmocka_unit_test(test_peep_string_queue),
      cmocka_unit_test(test_concat_string_queue)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
