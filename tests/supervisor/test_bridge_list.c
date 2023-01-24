#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "supervisor/bridge_list.h"
#include "utils/log.h"
#include "utils/net.h"

static void test_add_bridge_mac(void **state) {
  (void)state; /* unused */

  struct bridge_mac_list *bridge_list = init_bridge_list();
  char *mac_str_1 = "11:22:33:44:55:66";
  char *mac_str_2 = "aa:bb:cc:dd:ee:ff";
  char *mac_str_3 = "12:23:34:45:56:67";
  char *mac_str_4 = "FF:FF:FF:FF:FF:FF";
  uint8_t mac_addr_1[ETHER_ADDR_LEN];
  uint8_t mac_addr_2[ETHER_ADDR_LEN];
  uint8_t mac_addr_3[ETHER_ADDR_LEN];
  uint8_t mac_addr_4[ETHER_ADDR_LEN];
  convert_ascii2mac(mac_str_1, mac_addr_1);
  convert_ascii2mac(mac_str_2, mac_addr_2);
  convert_ascii2mac(mac_str_3, mac_addr_3);
  convert_ascii2mac(mac_str_4, mac_addr_4);

  int ret = add_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  assert_int_equal(ret, 1);

  ret = add_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
  assert_int_equal(ret, 1);

  ret = add_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
  assert_int_equal(ret, 1);

  ret = add_bridge_mac(bridge_list, NULL, mac_addr_2);
  assert_int_equal(ret, -1);

  ret = add_bridge_mac(bridge_list, NULL, NULL);
  assert_int_equal(ret, -1);

  ret = add_bridge_mac(NULL, NULL, NULL);
  assert_int_equal(ret, -1);

  ret = add_bridge_mac(bridge_list, mac_addr_1, mac_addr_1);
  assert_int_equal(ret, -1);

  struct bridge_mac_list_tuple e =
      get_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_2, mac_addr_1);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_3, mac_addr_2);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_4, mac_addr_3);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_4, mac_addr_1);
  assert_null(e.left_edge);
  assert_null(e.right_edge);

  free_bridge_list(bridge_list);

  bridge_list = init_bridge_list();
  e = get_bridge_mac(bridge_list, mac_addr_4, mac_addr_1);
  assert_null(e.left_edge);
  assert_null(e.right_edge);

  free_bridge_list(bridge_list);
}

static void test_remove_bridge_mac(void **state) {
  (void)state; /* unused */

  struct bridge_mac_list *bridge_list = init_bridge_list();
  char *mac_str_1 = "11:22:33:44:55:66";
  char *mac_str_2 = "aa:bb:cc:dd:ee:ff";
  char *mac_str_3 = "12:23:34:45:56:67";
  char *mac_str_4 = "FF:FF:FF:FF:FF:FF";
  uint8_t mac_addr_1[ETHER_ADDR_LEN];
  uint8_t mac_addr_2[ETHER_ADDR_LEN];
  uint8_t mac_addr_3[ETHER_ADDR_LEN];
  uint8_t mac_addr_4[ETHER_ADDR_LEN];
  convert_ascii2mac(mac_str_1, mac_addr_1);
  convert_ascii2mac(mac_str_2, mac_addr_2);
  convert_ascii2mac(mac_str_3, mac_addr_3);
  convert_ascii2mac(mac_str_4, mac_addr_4);

  int ret = remove_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  assert_int_equal(ret, 0);

  struct bridge_mac_list_tuple e =
      get_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  assert_null(e.left_edge);
  assert_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_2, mac_addr_1);
  assert_null(e.left_edge);
  assert_null(e.right_edge);

  ret = add_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  assert_int_equal(ret, 1);

  ret = add_bridge_mac(bridge_list, mac_addr_2, mac_addr_1);
  assert_int_equal(ret, 0);

  ret = add_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
  assert_int_equal(ret, 1);

  ret = add_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
  assert_int_equal(ret, 1);

  e = get_bridge_mac(bridge_list, mac_addr_2, mac_addr_1);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_3, mac_addr_2);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_4, mac_addr_3);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  ret = remove_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  assert_int_equal(ret, 0);

  e = get_bridge_mac(bridge_list, mac_addr_2, mac_addr_1);
  assert_null(e.left_edge);
  assert_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_3, mac_addr_2);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  e = get_bridge_mac(bridge_list, mac_addr_4, mac_addr_3);
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  ret = remove_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
  assert_int_equal(ret, 0);

  ret = remove_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
  assert_int_equal(ret, 0);

  e = get_bridge_mac(bridge_list, mac_addr_3, mac_addr_2);
  assert_null(e.left_edge);
  assert_null(e.right_edge);

  free_bridge_list(bridge_list);
}

static void test_get_all_bridge_edges(void **state) {
  (void)state; /* unused */

  struct bridge_mac_tuple *p = NULL;
  UT_array *tuple_list_arr;
  struct bridge_mac_list *bridge_list = init_bridge_list();
  char *mac_str_1 = "11:22:33:44:55:66";
  char *mac_str_2 = "aa:bb:cc:dd:ee:ff";
  char *mac_str_3 = "12:23:34:45:56:67";
  char *mac_str_4 = "FF:FF:FF:FF:FF:FF";
  uint8_t mac_addr_1[ETHER_ADDR_LEN];
  uint8_t mac_addr_2[ETHER_ADDR_LEN];
  uint8_t mac_addr_3[ETHER_ADDR_LEN];
  uint8_t mac_addr_4[ETHER_ADDR_LEN];
  convert_ascii2mac(mac_str_1, mac_addr_1);
  convert_ascii2mac(mac_str_2, mac_addr_2);
  convert_ascii2mac(mac_str_3, mac_addr_3);
  convert_ascii2mac(mac_str_4, mac_addr_4);

  int count = get_all_bridge_edges(bridge_list, &tuple_list_arr);
  assert_int_equal(count, 0);
  utarray_free(tuple_list_arr);

  add_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);

  count = get_all_bridge_edges(bridge_list, &tuple_list_arr);
  assert_int_equal(count, 2);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, NULL);
  assert_memory_equal(p->src_addr, mac_addr_2, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_1, ETHER_ADDR_LEN);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, p);
  assert_memory_equal(p->src_addr, mac_addr_1, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_2, ETHER_ADDR_LEN);
  utarray_free(tuple_list_arr);

  add_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
  add_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
  count = get_all_bridge_edges(bridge_list, &tuple_list_arr);
  assert_int_equal(count, 6);
  assert_int_equal(utarray_len(tuple_list_arr), 6);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, NULL);
  assert_memory_equal(p->src_addr, mac_addr_4, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_3, ETHER_ADDR_LEN);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, p);
  assert_memory_equal(p->src_addr, mac_addr_3, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_4, ETHER_ADDR_LEN);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, p);
  assert_memory_equal(p->src_addr, mac_addr_3, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_2, ETHER_ADDR_LEN);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, p);
  assert_memory_equal(p->src_addr, mac_addr_2, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_3, ETHER_ADDR_LEN);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, p);
  assert_memory_equal(p->src_addr, mac_addr_2, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_1, ETHER_ADDR_LEN);
  p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, p);
  assert_memory_equal(p->src_addr, mac_addr_1, ETHER_ADDR_LEN);
  assert_memory_equal(p->dst_addr, mac_addr_2, ETHER_ADDR_LEN);

  utarray_free(tuple_list_arr);
  free_bridge_list(bridge_list);
}

static void test_get_src_mac_list(void **state) {
  (void)state; /* unused */

  uint8_t *p;
  UT_array *mac_list_arr;
  struct bridge_mac_list *bridge_list = init_bridge_list();
  char *mac_str_1 = "11:22:33:44:55:66";
  char *mac_str_2 = "aa:bb:cc:dd:ee:ff";
  char *mac_str_3 = "12:23:34:45:56:67";
  char *mac_str_4 = "FF:FF:FF:FF:FF:FF";
  uint8_t mac_addr_1[ETHER_ADDR_LEN];
  uint8_t mac_addr_2[ETHER_ADDR_LEN];
  uint8_t mac_addr_3[ETHER_ADDR_LEN];
  uint8_t mac_addr_4[ETHER_ADDR_LEN];
  convert_ascii2mac(mac_str_1, mac_addr_1);
  convert_ascii2mac(mac_str_2, mac_addr_2);
  convert_ascii2mac(mac_str_3, mac_addr_3);
  convert_ascii2mac(mac_str_4, mac_addr_4);

  int count = get_src_mac_list(bridge_list, mac_addr_1, &mac_list_arr);
  assert_int_equal(count, 0);
  utarray_free(mac_list_arr);

  add_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  add_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
  add_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
  count = get_src_mac_list(bridge_list, mac_addr_1, &mac_list_arr);
  assert_int_equal(count, 1);

  p = (uint8_t *)utarray_next(mac_list_arr, NULL);
  assert_memory_equal(p, mac_addr_2, ETHER_ADDR_LEN);
  utarray_free(mac_list_arr);

  add_bridge_mac(bridge_list, mac_addr_1, mac_addr_3);
  add_bridge_mac(bridge_list, mac_addr_1, mac_addr_4);
  count = get_src_mac_list(bridge_list, mac_addr_1, &mac_list_arr);
  assert_int_equal(count, 3);
  p = (uint8_t *)utarray_next(mac_list_arr, NULL);
  assert_memory_equal(p, mac_addr_4, ETHER_ADDR_LEN);
  p = (uint8_t *)utarray_next(mac_list_arr, p);
  assert_memory_equal(p, mac_addr_3, ETHER_ADDR_LEN);
  p = (uint8_t *)utarray_next(mac_list_arr, p);
  assert_memory_equal(p, mac_addr_2, ETHER_ADDR_LEN);
  utarray_free(mac_list_arr);

  count = get_src_mac_list(bridge_list, mac_addr_3, &mac_list_arr);
  assert_int_equal(count, 3);
  p = (uint8_t *)utarray_next(mac_list_arr, NULL);
  assert_memory_equal(p, mac_addr_1, ETHER_ADDR_LEN);
  p = (uint8_t *)utarray_next(mac_list_arr, p);
  assert_memory_equal(p, mac_addr_4, ETHER_ADDR_LEN);
  p = (uint8_t *)utarray_next(mac_list_arr, p);
  assert_memory_equal(p, mac_addr_2, ETHER_ADDR_LEN);
  utarray_free(mac_list_arr);

  count = get_src_mac_list(bridge_list, mac_addr_2, &mac_list_arr);
  assert_int_equal(count, 2);
  p = (uint8_t *)utarray_next(mac_list_arr, NULL);
  assert_memory_equal(p, mac_addr_3, ETHER_ADDR_LEN);
  p = (uint8_t *)utarray_next(mac_list_arr, p);
  assert_memory_equal(p, mac_addr_1, ETHER_ADDR_LEN);
  utarray_free(mac_list_arr);

  int ret = remove_bridge_mac(bridge_list, mac_addr_1, mac_addr_4);
  assert_int_equal(ret, 0);
  ret = remove_bridge_mac(bridge_list, mac_addr_4, mac_addr_3);
  assert_int_equal(ret, 0);

  count = get_src_mac_list(bridge_list, mac_addr_4, &mac_list_arr);
  assert_int_equal(count, 0);
  utarray_free(mac_list_arr);

  free_bridge_list(bridge_list);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_add_bridge_mac),
      cmocka_unit_test(test_remove_bridge_mac),
      cmocka_unit_test(test_get_all_bridge_edges),
      cmocka_unit_test(test_get_src_mac_list)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
