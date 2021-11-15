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
#include "utils/if.h"
#include "utils/utarray.h"

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL, NULL};

static void test_iface_exists(void **state)
{
  (void) state; /* unused */

  /* Testing iface_exists for lo */
  bool ret = iface_exists("lo");
  assert_true(ret);

  /* Testing iface_exists for chuppa123 */
  ret = iface_exists("chuppa123");
  assert_false(ret);

  /* Testing iface_exists for NULL */
  ret = iface_exists(NULL);
  assert_false(ret);

  /* Testing iface_exists for "" */
  ret = iface_exists("");
  assert_false(ret);
}

static void test_ip_2_nbo(void **state)
{
  (void) state; /* unused */

  in_addr_t addr;
  in_addr_t subnet = 0x0A000100;

  int ret = ip_2_nbo("10.0.1.23", "255.255.255.0", &addr);
  assert_int_equal(ret, 0);
  assert_memory_equal(&addr, &subnet, sizeof(uint32_t));

  ret = ip_2_nbo("x.0.1.23", "255.255.255.0", &addr);
  assert_int_equal(ret, -1);
}

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

static void test_validate_ipv4_string(void **state)
{
  bool ret = validate_ipv4_string("10.0.0.1");
  assert_true(ret);

  ret = validate_ipv4_string("10.0.0");
  assert_false(ret);

  ret = validate_ipv4_string("a.b.c.d");
  assert_false(ret);

  ret = validate_ipv4_string("0.0.0.0");
  assert_true(ret);

  ret = validate_ipv4_string("127.0.0.1/32");
  assert_true(ret);

  ret = validate_ipv4_string("127.0.0.1/");
  assert_false(ret);

  ret = validate_ipv4_string("127.0.0.1/33");
  assert_false(ret);

  ret = validate_ipv4_string("127.0.0.1/3a");
  assert_false(ret);
}


int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_iface_exists),
    cmocka_unit_test(test_ip_2_nbo),
    cmocka_unit_test(test_get_if_mapper),
    cmocka_unit_test(test_put_if_mapper),
    cmocka_unit_test(test_find_subnet_address),
    cmocka_unit_test(test_validate_ipv4_string)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
