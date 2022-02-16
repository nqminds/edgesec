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

#include "subnet/subnet_service.h"

#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/utarray.h"
#include "utils/net.h"
#include "utils/iface_mapper.h"

static const UT_icd netif_info_icd = {sizeof(netif_info_t), NULL, NULL, NULL};
static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL, NULL};

bool __wrap_iface_exists(const char *ifname);
UT_array *__wrap_get_netiw_info(void);
bool __wrap_iwace_isvlan(uint32_t wiphy);
bool __wrap_create_interface(char *if_name, char *type);
bool __wrap_set_interface_ip(char *ip_addr, char *brd_addr, char *if_name);
bool __wrap_set_interface_state(char *if_name, bool state);
UT_array *__wrap_get_interfaces(int if_id);
unsigned int __wrap_if_nametoindex (const char *__ifname);

bool __wrap_iface_exists(const char *ifname)
{
  check_expected(ifname);
  return mock_type(bool);
}

UT_array *__wrap_get_netiw_info(void)
{
  return mock_type(UT_array *);
}

bool __wrap_iwace_isvlan(uint32_t wiphy)
{
  if (!wiphy) return true;

  return false;
}

bool __wrap_create_interface(char *if_name, char *type)
{
  (void) if_name;
  (void) type;

  return true;
}

bool __wrap_set_interface_ip(char *ip_addr, char *brd_addr, char *if_name)
{
  (void) ip_addr;
  (void) brd_addr;
  (void) if_name;

  return true;
}

bool __wrap_set_interface_state(char *if_name, bool state)
{
  (void) if_name;
  (void) state;

  return true;
}

unsigned int __wrap_if_nametoindex (const char *__ifname)
{
  if (!strcmp(__ifname, "nat_test"))
    return 1;
  return 0;
}

UT_array *__wrap_get_interfaces(int if_id)
{
  (void) if_id;

  UT_array *arr = NULL;
  netif_info_t el;
  strcpy(el.ifname, "nat_test");
  el.ifindex = 1;
  strcpy(el.ip_addr, "127.0.0.1");
  el.ifa_family = AF_INET;
  utarray_new(arr, &netif_info_icd);
  utarray_push_back(arr, &el);

  return arr;
}

static void test_1_get_nat_if_ip(void **state)
{
  (void) state; /* unused */

  char ip_buf[OS_INET_ADDRSTRLEN];
  os_memset(ip_buf, 0, OS_INET_ADDRSTRLEN);
  bool ret = get_nat_if_ip("nat_test", ip_buf);

  assert_true(ret);
  assert_string_equal(ip_buf, "127.0.0.1");
}

static void test_2_get_nat_if_ip(void **state)
{
  (void) state; /* unused */

  char ip_buf[OS_INET_ADDRSTRLEN];
  os_memset(ip_buf, 0, OS_INET_ADDRSTRLEN);

  bool ret = get_nat_if_ip("wlan0", ip_buf);

  assert_false(ret);
}

static void test_create_subnet_ifs(void **state)
{
  (void) state; /* unused */

  UT_array *ifinfo_array = NULL;
  utarray_new(ifinfo_array, &config_ifinfo_icd);
  config_ifinfo_t el;
  strcpy(el.ifname, "wlan0");
  strcpy(el.ip_addr, "127.0.0.1");
  strcpy(el.brd_addr, "127.0.0.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(ifinfo_array, &el);

  bool ret = create_subnet_ifs(ifinfo_array, false);
  utarray_free(ifinfo_array);
  assert_true(ret);

  ifinfo_array = NULL;
  ret = create_subnet_ifs(ifinfo_array, false);
  assert_false(ret);
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
    cmocka_unit_test(test_1_get_nat_if_ip),
    cmocka_unit_test(test_2_get_nat_if_ip),
    cmocka_unit_test(test_create_subnet_ifs),
    cmocka_unit_test(test_create_if_mapper),
    cmocka_unit_test(test_create_vlan_mapper)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
