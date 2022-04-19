#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils/log.h"
#include "utils/os.h"
#include "dns/mdns_mapper.h"

static void test_put_mdns_answer_mapper(void **state) {
  (void)state; /* unused */

  hmap_mdns_conn *imap = NULL;
  uint8_t ip[IP_ALEN] = {10, 0, 0, 23};
  uint8_t ip1[IP_ALEN] = {10, 0, 0, 24};

  struct mdns_answer_entry answer = {};

  assert_int_equal(put_mdns_answer_mapper(&imap, ip, &answer), 0);
  assert_int_equal(put_mdns_answer_mapper(&imap, ip1, &answer), 0);

  free_mdns_mapper(&imap);
}

static void test_put_mdns_query_mapper(void **state) {
  (void)state;

  hmap_mdns_conn *imap = NULL;
  uint8_t ip[IP_ALEN] = {10, 0, 0, 23};
  uint8_t ip1[IP_ALEN] = {10, 0, 0, 24};

  struct mdns_query_entry query = {};

  assert_int_equal(put_mdns_query_mapper(&imap, ip, &query), 0);
  assert_int_equal(put_mdns_query_mapper(&imap, ip1, &query), 0);

  free_mdns_mapper(&imap);
}

static void test_check_mdns_mapper_req(void **state) {
  (void)state; /* unused */

  hmap_mdns_conn *imap = NULL;
  uint8_t ip[IP_ALEN] = {10, 0, 0, 23};
  uint8_t ip1[IP_ALEN] = {10, 0, 0, 24};
  char *test1 = "test1";
  char *test2 = "test2";

  struct mdns_query_entry query = {};
  struct mdns_answer_entry answer = {};
  strcpy(query.qname, test1);
  strcpy(answer.rrname, test2);

  assert_int_equal(put_mdns_answer_mapper(&imap, ip, &answer), 0);
  assert_int_equal(check_mdns_mapper_req(&imap, ip, MDNS_REQUEST_ANSWER), 1);
  assert_int_equal(check_mdns_mapper_req(&imap, ip, MDNS_REQUEST_QUERY), 0);
  assert_int_equal(put_mdns_query_mapper(&imap, ip, &query), 0);
  assert_int_equal(check_mdns_mapper_req(&imap, ip, MDNS_REQUEST_ANSWER), 1);
  assert_int_equal(check_mdns_mapper_req(&imap, ip, MDNS_REQUEST_QUERY), 1);
  assert_int_equal(put_mdns_query_mapper(&imap, ip1, &query), 0);
  assert_int_equal(check_mdns_mapper_req(&imap, ip1, MDNS_REQUEST_ANSWER), 0);
  assert_int_equal(check_mdns_mapper_req(&imap, ip1, MDNS_REQUEST_QUERY), 1);

  free_mdns_mapper(&imap);
}

int main(int argc, char *argv[]) {
  (void)argc; /* unused */
  (void)argv; /* unused */

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_put_mdns_answer_mapper),
      cmocka_unit_test(test_put_mdns_query_mapper),
      cmocka_unit_test(test_check_mdns_mapper_req)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
