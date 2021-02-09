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

#include "supervisor/bridge_list.h"
#include "utils/log.h"

static void test_add_bridge_mac(void **state)
{
  (void) state; /* unused */

  struct bridge_mac_list *bridge_list = init_bridge_list();
  char *mac_str_1 = "11:22:33:44:55:66";
  char *mac_str_2 = "aa:bb:cc:dd:ee:ff";
  char *mac_str_3 = "12:23:34:45:56:67";
  char *mac_str_4 = "FF:FF:FF:FF:FF:FF";
  uint8_t mac_addr_1[ETH_ALEN];
  uint8_t mac_addr_2[ETH_ALEN];
  uint8_t mac_addr_3[ETH_ALEN];
  uint8_t mac_addr_4[ETH_ALEN];
  hwaddr_aton2(mac_str_1, mac_addr_1);
  hwaddr_aton2(mac_str_2, mac_addr_2);
  hwaddr_aton2(mac_str_3, mac_addr_3);
  hwaddr_aton2(mac_str_4, mac_addr_4);

  int ret = add_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
  assert_int_equal(ret, 0);

  ret = add_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
  assert_int_equal(ret, 0);
  
  ret = add_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
  assert_int_equal(ret, 0);

  ret = add_bridge_mac(bridge_list, NULL, mac_addr_2);
  assert_int_equal(ret, -1);

  ret = add_bridge_mac(bridge_list, NULL, NULL);
  assert_int_equal(ret, -1);

  ret = add_bridge_mac(NULL, NULL, NULL);
  assert_int_equal(ret, -1);

  ret = add_bridge_mac(bridge_list, mac_addr_1, mac_addr_1);
  assert_int_equal(ret, -1);

  struct bridge_mac_list_tuple e = get_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
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
  assert_non_null(e.left_edge);
  assert_non_null(e.right_edge);

  free_bridge_list(bridge_list);

  bridge_list = init_bridge_list();
  e = get_bridge_mac(bridge_list, mac_addr_4, mac_addr_1);
  assert_null(e.left_edge);
  assert_null(e.right_edge);

  free_bridge_list(bridge_list);
}

// static void test_remove_bridge_mac(void **state)
// {
//   (void) state; /* unused */

//   struct bridge_mac_list *bridge_list = init_bridge_list();
//   char *mac_str_1 = "11:22:33:44:55:66";
//   char *mac_str_2 = "aa:bb:cc:dd:ee:ff";
//   char *mac_str_3 = "12:23:34:45:56:67";
//   char *mac_str_4 = "FF:FF:FF:FF:FF:FF";
//   uint8_t mac_addr_1[ETH_ALEN];
//   uint8_t mac_addr_2[ETH_ALEN];
//   uint8_t mac_addr_3[ETH_ALEN];
//   uint8_t mac_addr_4[ETH_ALEN];
//   hwaddr_aton2(mac_str_1, mac_addr_1);
//   hwaddr_aton2(mac_str_2, mac_addr_2);
//   hwaddr_aton2(mac_str_3, mac_addr_3);
//   hwaddr_aton2(mac_str_4, mac_addr_4);

//   int ret = remove_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
//   assert_int_equal(ret, 0);

//   ret = add_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
//   assert_int_equal(ret, 0);

//   ret = add_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
//   assert_int_equal(ret, 0);
  
//   ret = add_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
//   assert_int_equal(ret, 0);

//   ret = remove_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
//   assert_int_equal(ret, 0);

//   struct bridge_mac_list *e = get_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);
//   assert_null(e);

//   e = get_bridge_mac(bridge_list, mac_addr_2, mac_addr_1);
//   assert_null(e);

//   e = get_bridge_mac(bridge_list, mac_addr_3, mac_addr_2);
//   assert_non_null(e);

//   e = get_bridge_mac(bridge_list, mac_addr_4, mac_addr_3);
//   assert_non_null(e);
//   free_bridge_list(bridge_list);
//   bridge_list = NULL;
//   e = get_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
//   assert_null(e);
// }

// static void test_get_bridge_tuple_list(void **state)
// {
//   (void) state; /* unused */

//   struct bridge_mac_tuple *p = NULL;
//   UT_array *tuple_list_arr;
//   struct bridge_mac_list *bridge_list = init_bridge_list();
//   char *mac_str_1 = "11:22:33:44:55:66";
//   char *mac_str_2 = "aa:bb:cc:dd:ee:ff";
//   char *mac_str_3 = "12:23:34:45:56:67";
//   char *mac_str_4 = "FF:FF:FF:FF:FF:FF";
//   uint8_t mac_addr_1[ETH_ALEN];
//   uint8_t mac_addr_2[ETH_ALEN];
//   uint8_t mac_addr_3[ETH_ALEN];
//   uint8_t mac_addr_4[ETH_ALEN];
//   hwaddr_aton2(mac_str_1, mac_addr_1);
//   hwaddr_aton2(mac_str_2, mac_addr_2);
//   hwaddr_aton2(mac_str_3, mac_addr_3);
//   hwaddr_aton2(mac_str_4, mac_addr_4);

//   int count = get_bridge_tuple_list(bridge_list, NULL, &tuple_list_arr);
//   assert_int_equal(count, 0);

//   add_bridge_mac(bridge_list, mac_addr_1, mac_addr_2);

//   count = get_bridge_tuple_list(bridge_list, NULL, &tuple_list_arr);
//   assert_int_equal(count, 1);
//   p = (struct bridge_mac_tuple *) utarray_next(tuple_list_arr, p);
//   assert_int_equal(memcmp(p->left_addr, mac_addr_1, ETH_ALEN), 0);
//   assert_int_equal(memcmp(p->right_addr, mac_addr_2, ETH_ALEN), 0);
//   utarray_free(tuple_list_arr);

//   add_bridge_mac(bridge_list, mac_addr_2, mac_addr_3);
//   add_bridge_mac(bridge_list, mac_addr_3, mac_addr_4);
//   count = get_bridge_tuple_list(bridge_list, NULL, &tuple_list_arr);
//   assert_int_equal(count, 3);
//   assert_int_equal(utarray_len(tuple_list_arr), 3);
//   p = (struct bridge_mac_tuple *) utarray_next(tuple_list_arr, NULL);
//   assert_int_equal(memcmp(p->left_addr, mac_addr_3, ETH_ALEN), 0);
//   assert_int_equal(memcmp(p->right_addr, mac_addr_4, ETH_ALEN), 0);
//   p = (struct bridge_mac_tuple *) utarray_next(tuple_list_arr, p);
//   assert_int_equal(memcmp(p->left_addr, mac_addr_2, ETH_ALEN), 0);
//   assert_int_equal(memcmp(p->right_addr, mac_addr_3, ETH_ALEN), 0);
//   p = (struct bridge_mac_tuple *) utarray_next(tuple_list_arr, p);
//   assert_int_equal(memcmp(p->left_addr, mac_addr_1, ETH_ALEN), 0);
//   assert_int_equal(memcmp(p->right_addr, mac_addr_2, ETH_ALEN), 0);

//   // count = get_bridge_tuple_list(bridge_list, mac_addr_1, &tuple_list_arr);
//   // assert_int_equal(count, 1);
//   // p = (struct bridge_mac_tuple *) utarray_next(tuple_list_arr, NULL);
//   // assert_int_equal(memcmp(p->left_addr, mac_addr_1, ETH_ALEN), 0);
//   // assert_int_equal(memcmp(p->right_addr, mac_addr_2, ETH_ALEN), 0);
//   // utarray_free(tuple_list_arr);

//   // add_bridge_mac(bridge_list, mac_addr_4, mac_addr_2);
//   // count = get_bridge_tuple_list(bridge_list, mac_addr_2, &tuple_list_arr);
//   // assert_int_equal(count, 2);

//   utarray_free(tuple_list_arr);
//   free_bridge_list(bridge_list);
// }

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_add_bridge_mac)//,
    // cmocka_unit_test(test_remove_bridge_mac),
    // cmocka_unit_test(test_get_bridge_tuple_list)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
