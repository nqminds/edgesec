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
#include "utils/iface_mapper.h"
#include "utils/net.h"
#include "utils/utarray.h"

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL, NULL};

static void test_get_if_mapper(void **state)
{
  (void) state; /* unused */
  hmap_if_conn *hmap = NULL;
  char ifname[IFNAMSIZ];

  put_if_mapper(&hmap, 0x0A000100, "br2");

  bool ret = get_if_mapper(&hmap, 0x0A000100, ifname);
  assert_true(ret);

  assert_int_equal(strcmp(ifname, "br2"), 0);

  ret = get_if_mapper(&hmap, 0x0A000101, ifname);
  assert_false(ret);
  free_if_mapper(&hmap);
}

static void test_put_if_mapper(void **state)
{
  (void) state; /* unused */

  hmap_if_conn *hmap = NULL;
  char ifname[IFNAMSIZ];

  bool ret = put_if_mapper(&hmap, 0x0A000100, "br2");
  assert_true(ret);

  ret = get_if_mapper(&hmap, 0x0A000100, ifname);
  assert_true(ret);

  assert_int_equal(strcmp(ifname, "br2"), 0);
  free_if_mapper(&hmap);
}

static void test_find_subnet_address(void **state)
{
  (void) state; /* unused */

  UT_array *config_ifinfo_arr;
  utarray_new(config_ifinfo_arr, &config_ifinfo_icd);

  config_ifinfo_t el;
  in_addr_t config_addr;
  in_addr_t subnet_addr;

  el.vlanid = 0;
  strcpy(el.ifname, "if0");
  strcpy(el.ip_addr, "10.0.0.1");
  strcpy(el.brd_addr, "10.0.0.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  el.vlanid = 1;
  strcpy(el.ifname, "if1");
  strcpy(el.ip_addr, "10.0.1.1");
  strcpy(el.brd_addr, "10.0.1.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  el.vlanid = 2;
  strcpy(el.ifname, "if2");
  strcpy(el.ip_addr, "10.0.2.1");
  strcpy(el.brd_addr, "10.0.2.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  el.vlanid = 3;
  strcpy(el.ifname, "if3");
  strcpy(el.ip_addr, "10.0.3.1");
  strcpy(el.brd_addr, "10.0.3.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  el.vlanid = 4;
  strcpy(el.ifname, "if4");
  strcpy(el.ip_addr, "10.0.4.1");
  strcpy(el.brd_addr, "10.0.4.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  el.vlanid = 5;
  strcpy(el.ifname, "if5");
  strcpy(el.ip_addr, "10.0.5.1");
  strcpy(el.brd_addr, "10.0.5.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  el.vlanid = 6;
  strcpy(el.ifname, "if6");
  strcpy(el.ip_addr, "10.0.6.1");
  strcpy(el.brd_addr, "10.0.6.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  el.vlanid = 7;
  strcpy(el.ifname, "if7");
  strcpy(el.ip_addr, "10.0.7.1");
  strcpy(el.brd_addr, "10.0.7.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config_ifinfo_arr, &el);

  int ret = find_subnet_address(config_ifinfo_arr, "10.0.6.45", &subnet_addr);
  assert_int_equal(ret, 0);

  ip_2_nbo("10.0.6.1", "255.255.255.0", &config_addr);
  assert_memory_equal((void*)&config_addr, (void*)&subnet_addr, sizeof(in_addr_t));

  ret = find_subnet_address(config_ifinfo_arr, "10.1.6.45", &subnet_addr);
  assert_int_equal(ret, 1);

  ret = find_subnet_address(config_ifinfo_arr, "test", &subnet_addr);
  assert_int_equal(ret, -1);

  utarray_free(config_ifinfo_arr);
}

static void test_create_if_mapper(void **state)
{
  (void) state; /* unused */

  UT_array *arr;
  hmap_if_conn *hmap = NULL;
  config_ifinfo_t el;
  in_addr_t addr = 0;
  char *ip1 = "10.0.0.1";
  char *ip2 = "185.0.0.0";
  char *brd1 = "10.0.0.255";
  char *brd2 = "185.159.255.255";
  char *mask1 = "255.255.255.0";
  char *mask2 = "255.240.0.0";
  char ifname[30];

  utarray_new(arr, &config_ifinfo_icd);
  assert_true(create_if_mapper(arr, &hmap));
  utarray_free(arr);
  free_if_mapper(&hmap);

  utarray_new(arr, &config_ifinfo_icd);
  os_memset(&el, 0, sizeof(config_ifinfo_t));
  el.vlanid = 1;
  strcpy(el.ifname, "br0");
  strcpy(el.ip_addr, ip1);
  strcpy(el.brd_addr, brd1);
  strcpy(el.subnet_mask, mask1);
  utarray_push_back(arr, &el);

  assert_true(create_if_mapper(arr, &hmap));
  ip_2_nbo(ip1, mask1, &addr);
  assert_true(get_if_mapper(&hmap, addr, ifname));
  assert_string_equal(ifname, "br0");
  addr = 0;
  ip_2_nbo(ip2, mask2, &addr);
  assert_false(get_if_mapper(&hmap, addr, ifname));

  os_memset(&el, 0, sizeof(config_ifinfo_t));
  el.vlanid = 2;
  strcpy(el.ifname, "br1");
  strcpy(el.ip_addr, ip2);
  strcpy(el.brd_addr, brd2);
  strcpy(el.subnet_mask, mask2);
  utarray_push_back(arr, &el);
  free_if_mapper(&hmap);

  assert_true(create_if_mapper(arr, &hmap));
  addr = 0;
  ip_2_nbo(ip2, mask2, &addr);
  assert_true(get_if_mapper(&hmap, addr, ifname));

  utarray_free(arr);
  free_if_mapper(&hmap);
}

static void test_create_vlan_mapper(void **state)
{
  (void) state; /* unused */
  UT_array *arr = NULL;
  hmap_vlan_conn *hmap = NULL;
  config_ifinfo_t el;
  struct vlan_conn conn;

  char *ip1 = "10.0.0.1";
  char *ip2 = "185.0.0.0";
  char *brd1 = "10.0.0.255";
  char *brd2 = "185.159.255.255";
  char *mask1 = "255.255.255.0";
  char *mask2 = "255.240.0.0";

  utarray_new(arr, &config_ifinfo_icd);

  assert_true(create_vlan_mapper(arr, &hmap));
  free_vlan_mapper(&hmap);
  utarray_free(arr);

  utarray_new(arr, &config_ifinfo_icd);
  os_memset(&el, 0, sizeof(config_ifinfo_t));
  el.vlanid = 1;
  strcpy(el.ifname, "br0");
  strcpy(el.ip_addr, ip1);
  strcpy(el.brd_addr, brd1);
  strcpy(el.subnet_mask, mask1);
  utarray_push_back(arr, &el);

  os_memset(&el, 0, sizeof(config_ifinfo_t));
  el.vlanid = 2;
  strcpy(el.ifname, "br1");
  strcpy(el.ip_addr, ip2);
  strcpy(el.brd_addr, brd2);
  strcpy(el.subnet_mask, mask2);
  utarray_push_back(arr, &el);

  assert_true(create_vlan_mapper(arr, &hmap));

  assert_int_equal(get_vlan_mapper(&hmap, 1, &conn), 1);
  assert_string_equal(conn.ifname, "br0");

  assert_int_equal(get_vlan_mapper(&hmap, 2, &conn), 1);
  assert_string_equal(conn.ifname, "br1");

  assert_int_equal(get_vlan_mapper(&hmap, 0, &conn), 0);

  free_vlan_mapper(&hmap);
  utarray_free(arr);
}

int main(int argc, char *argv[])
{  
  (void) argc;
  (void) argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_get_if_mapper),
    cmocka_unit_test(test_put_if_mapper),
    cmocka_unit_test(test_find_subnet_address),
    cmocka_unit_test(test_create_if_mapper),
    cmocka_unit_test(test_create_vlan_mapper)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
