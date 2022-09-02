#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils/log.h"
#include "utils/os.h"
#include "dns/mdns_list.h"

static void test_push_mdns_list(void **state) {
  (void)state; /* unused */
  char *name = "test";
  char *name1 = "test1";
  struct mdns_list_info info = {.name = name, .request = MDNS_REQUEST_QUERY};
  struct mdns_list *list = init_mdns_list();

  assert_non_null(list);
  assert_int_equal(push_mdns_list(list, &info), 0);
  assert_int_equal(check_mdns_list_req(list, MDNS_REQUEST_QUERY), 1);
  assert_int_equal(check_mdns_list_req(list, MDNS_REQUEST_ANSWER), 0);

  info.request = MDNS_REQUEST_ANSWER;
  assert_int_equal(push_mdns_list(list, &info), 0);
  assert_int_equal(check_mdns_list_req(list, MDNS_REQUEST_QUERY), 1);
  assert_int_equal(check_mdns_list_req(list, MDNS_REQUEST_ANSWER), 1);

  assert_int_equal(push_mdns_list(list, &info), 0);
  assert_int_equal(dl_list_len(&list->list), 2);

  info.name = name1;
  assert_int_equal(push_mdns_list(list, &info), 0);
  assert_int_equal(dl_list_len(&list->list), 3);

  assert_int_equal(push_mdns_list(list, &info), 0);
  assert_int_equal(dl_list_len(&list->list), 3);
  info.request = MDNS_REQUEST_QUERY;
  assert_int_equal(push_mdns_list(list, &info), 0);
  assert_int_equal(dl_list_len(&list->list), 4);

  free_mdns_list(list);
}

static void test_init_mdns_list(void **state) {
  (void)state;

  struct mdns_list *list = NULL;
  list = init_mdns_list();
  assert_non_null(list);

  free_mdns_list(list);
}

static void test_check_mdns_list_req(void **state) {
  (void)state; /* unused */
  char *name = "test";
  struct mdns_list_info info = {.name = name, .request = MDNS_REQUEST_QUERY};
  struct mdns_list *list = init_mdns_list();

  assert_non_null(list);
  assert_int_equal(push_mdns_list(list, &info), 0);
  assert_int_equal(check_mdns_list_req(list, MDNS_REQUEST_QUERY), 1);
  assert_int_equal(check_mdns_list_req(list, MDNS_REQUEST_ANSWER), 0);

  free_mdns_list(list);
}

int main(int argc, char *argv[]) {
  (void)argc; /* unused */
  (void)argv; /* unused */

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_mdns_list),
      cmocka_unit_test(test_push_mdns_list),
      cmocka_unit_test(test_check_mdns_list_req)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
