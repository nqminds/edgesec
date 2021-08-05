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

static struct mac_conn el[6] = {
  {{0x04, 0xf0, 0x21, 0x5a, 0xf4, 0xc4}, 0, 0, 1, 0, {}, 0, {}, {'b', 'r', '0', '\0'}},
  {{0x30, 0x52, 0xcb, 0xe9, 0x00, 0x8f}, 0, 1, 0, 0, {}, 0, {}, {'b', 'r', '1', '\0'}},
  {{0x40, 0xb4, 0xcd, 0xf1, 0x18, 0xbc}, 0, 2, 1, 0, {}, 0, {}, {'b', 'r', '2', '\0'}},
  {{0x50, 0x80, 0xd0, 0x0b, 0x13, 0xaa}, 0, 3, 0, 0, {}, 0, {}, {'b', 'r', '3', '\0'}},
  {{0x60, 0x70, 0xc0, 0x0a, 0x23, 0xba}, 0, 4, 1, 0, {}, 0, {}, {'b', 'r', '4', '\0'}},
  {{0x00, 0x0f, 0x00, 0x70, 0x62, 0x88}, 0, 5, 1, 0, {}, 0, {}, {'b', 'r', '5', '\0'}}
};

static void test_put_mac_mapper(void **state)
{
  (void) state; /* unused */

  UT_array *mac_conn_arr;
  utarray_new(mac_conn_arr, &mac_conn_icd);  

  hmap_mac_conn *hmap = NULL;

  for (int i = 0; i < 6; i++) {
    assert_true(put_mac_mapper(&hmap, el[i]));
  }

  free_mac_mapper(&hmap);
}

static void test_get_mac_mapper(void **state)
{
  (void) state; /* unused */

  struct mac_conn_info info;
  hmap_mac_conn *hmap = NULL;
  assert_int_equal(get_mac_mapper(&hmap, el[0].mac_addr, &info), 0);
  assert_int_equal(get_mac_mapper(NULL, el[0].mac_addr, &info), -1);
  assert_int_equal(get_mac_mapper(&hmap, NULL, &info), -1);
  assert_int_equal(get_mac_mapper(&hmap, el[0].mac_addr, NULL), -1);

  for (int i = 0; i < 6; i++) {
    put_mac_mapper(&hmap, el[i]);
  }

  for (int i=0; i< 6; i++) {
    os_memset(&info, 0, sizeof(struct mac_conn_info));
    assert_int_equal(get_mac_mapper(&hmap, el[i].mac_addr, &info), 1);
    assert_string_equal(info.ifname, el[i].info.ifname);
  }

  free_mac_mapper(&hmap);
}

static void test_get_mac_list(void **state)
{
  (void) state; /* unused */
  int cnt;
  hmap_mac_conn *hmap = NULL;
  struct mac_conn *list;

  assert_int_equal(get_mac_list(&hmap, &list), 0);
  for (int i = 0; i < 6; i++) {
    put_mac_mapper(&hmap, el[i]);
  }

  cnt = get_mac_list(&hmap, &list);
  assert_int_equal(cnt, 6);
  free_mac_mapper(&hmap);
}


int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_put_mac_mapper),
    cmocka_unit_test(test_get_mac_mapper),
    cmocka_unit_test(test_get_mac_list)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
