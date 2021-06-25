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
#include "utils/utarray.h"
#include "supervisor/mac_mapper.h"

static const UT_icd mac_conn_icd = {sizeof(struct mac_conn), NULL, NULL, NULL};

static void test_put_mac_mapper(void **state)
{
  (void) state; /* unused */

  UT_array *mac_conn_arr;
  utarray_new(mac_conn_arr, &mac_conn_icd);  

  hmap_mac_conn *hmap = NULL;

  struct mac_conn el[6] = {
    {{0x04, 0xf0, 0x21, 0x5a, 0xf4, 0xc4}, 0, 0, 1, 0, {}, 0, {}, {'b', 'r', '0', '\0'}},
    {{0x30, 0x52, 0xcb, 0xe9, 0x00, 0x8f}, 0, 1, 0, 0, {}, 0, {}, {'b', 'r', '1', '\0'}},
    {{0x40, 0xb4, 0xcd, 0xf1, 0x18, 0xbc}, 0, 2, 1, 0, {}, 0, {}, {'b', 'r', '2', '\0'}},
    {{0x60, 0x70, 0xc0, 0x0a, 0x23, 0xba}, 0, 3, 0, 0, {}, 0, {}, {'b', 'r', '3', '\0'}},
    {{0x60, 0x70, 0xc0, 0x0a, 0x23, 0xba}, 0, 4, 1, 0, {}, 0, {}, {'b', 'r', '4', '\0'}},
    {{0x00, 0x0f, 0x00, 0x70, 0x62, 0x88}, 0, 5, 1, 0, {}, 0, {}, {'b', 'r', '5', '\0'}}
  };

  for (int i = 0; i < 5; i++)
    put_mac_mapper(&hmap, el[i]);

  struct mac_conn_info info;
  bool ret = get_mac_mapper(&hmap, el[1].mac_addr, &info);
  assert_true(ret);
  assert_int_equal(info.vlanid, el[1].info.vlanid);
  assert_int_equal(info.nat, el[1].info.nat);

  ret = get_mac_mapper(&hmap, el[3].mac_addr, &info);
  assert_true(ret);
  assert_int_equal(info.vlanid, el[4].info.vlanid);
  assert_int_equal(info.nat, el[4].info.nat);

  free_mac_mapper(&hmap);
}

static void test_create_mac_mapper(void **state)
{
  (void) state; /* unused */

  // hmap_mac_conn *hmap = NULL;

  // UT_array *mac_conn_arr;
  // utarray_new(mac_conn_arr, &mac_conn_icd);

  // struct mac_conn el[5] = {
  //   {{0x04, 0xf0, 0x21, 0x5a, 0xf4, 0xc4}, 0, 1},
  //   {{0x30, 0x52, 0xcb, 0xe9, 0x00, 0x8f}, 1, 0},
  //   {{0x40, 0xb4, 0xcd, 0xf1, 0x18, 0xbc}, 2, 1},
  //   {{0x60, 0x70, 0xc0, 0x0a, 0x23, 0xba}, 3, 0},
  //   {{0x00, 0x0f, 0x00, 0x70, 0x62, 0x88}, 4, 1}
  // };

  // char mac[ETH_ALEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

  // for (int i = 0; i < 5; i++)
  //   utarray_push_back(mac_conn_arr, &el[i]);

  // bool ret = create_mac_mapper(mac_conn_arr, &hmap);
  // assert_true(ret);

  // struct mac_conn_info info;

  // for (int i = 0; i< 5; i ++) {
  //   ret = get_mac_mapper(&hmap, el[i].mac_addr, &info);
  //   assert_true(ret);
  //   assert_int_equal(info.vlanid, el[i].info.vlanid);
  //   assert_int_equal(info.nat, el[i].info.nat);
  // }

  // ret = get_mac_mapper(&hmap, mac, &info);
  // assert_false(ret);

  // free_mac_mapper(&hmap);

  assert_false(true);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    // cmocka_unit_test(test_create_mac_mapper),
    cmocka_unit_test(test_put_mac_mapper)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
