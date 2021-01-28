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

#include "if_service.h"

#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/utarray.h"
#include "utils/iw.h"

static const UT_icd netif_info_icd = {sizeof(netif_info_t), NULL, NULL, NULL};
static const UT_icd netiw_info_icd = {sizeof(netiw_info_t), NULL, NULL, NULL};
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
  return true;
}

bool __wrap_set_interface_ip(char *ip_addr, char *brd_addr, char *if_name)
{
  return true;
}

bool __wrap_set_interface_state(char *if_name, bool state)
{
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

static void test_1_is_iw_vlan(void **state)
{
  (void) state; /* unused */

  UT_array *netif_list = NULL;
  netiw_info_t el;
  utarray_new(netif_list, &netiw_info_icd);

  expect_string(__wrap_iface_exists, ifname, "wlan0");
  will_return(__wrap_iface_exists, true);

  strcpy(el.ifname, "wlan0");
  el.wiphy = 0;
  utarray_push_back(netif_list, &el);

  strcpy(el.ifname, "wlan1");
  el.wiphy = 1;
  utarray_push_back(netif_list, &el);

  strcpy(el.ifname, "wlan2");
  el.wiphy = 2;
  utarray_push_back(netif_list, &el);

  will_return(__wrap_get_netiw_info, netif_list);

  bool ret = is_iw_vlan("wlan0");
  assert_true(ret);
}

static void test_2_is_iw_vlan(void **state)
{
  (void) state; /* unused */

  UT_array *netif_list = NULL;
  netiw_info_t el;
  utarray_new(netif_list, &netiw_info_icd);

  expect_string(__wrap_iface_exists, ifname, "wlan1");
  will_return(__wrap_iface_exists, true);

  strcpy(el.ifname, "wlan0");
  el.wiphy = 0;
  utarray_push_back(netif_list, &el);

  strcpy(el.ifname, "wlan1");
  el.wiphy = 1;
  utarray_push_back(netif_list, &el);

  strcpy(el.ifname, "wlan2");
  el.wiphy = 2;
  utarray_push_back(netif_list, &el);

  will_return(__wrap_get_netiw_info, netif_list);

  bool ret = is_iw_vlan("wlan1");
  assert_false(ret);
}

static void test_3_is_iw_vlan(void **state)
{
  (void) state; /* unused */

  expect_any(__wrap_iface_exists, ifname);
  will_return(__wrap_iface_exists, false);

  bool ret = is_iw_vlan(NULL);
  assert_false(ret);
}

static void test_1_get_valid_iw(void **state)
{
  (void) state; /* unused */
  char wifibuf[100];

  UT_array *netif_list = NULL;
  netiw_info_t el;
  utarray_new(netif_list, &netiw_info_icd);

  strcpy(el.ifname, "wlan0");
  el.wiphy = 0;
  utarray_push_back(netif_list, &el);

  strcpy(el.ifname, "wlan1");
  el.wiphy = 1;
  utarray_push_back(netif_list, &el);

  strcpy(el.ifname, "wlan2");
  el.wiphy = 2;
  utarray_push_back(netif_list, &el);

  will_return(__wrap_get_netiw_info, netif_list);

  char *wifi = get_valid_iw(wifibuf);
  assert_string_equal(wifi, "wlan0");
}

static void test_2_get_valid_iw(void **state)
{
  (void) state; /* unused */
  char wifibuf[100];
  UT_array *netif_list = NULL;
  netiw_info_t el;
  utarray_new(netif_list, &netiw_info_icd);

  strcpy(el.ifname, "wlan1");
  el.wiphy = 1;
  utarray_push_back(netif_list, &el);

  strcpy(el.ifname, "wlan2");
  el.wiphy = 2;
  utarray_push_back(netif_list, &el);

  will_return(__wrap_get_netiw_info, netif_list);

  char *wifi = get_valid_iw(wifibuf);
  assert_null(wifi);
}

static void test_3_get_valid_iw(void **state)
{
  (void) state; /* unused */
  char wifibuf[100];
  UT_array *netif_list = NULL;

  will_return(__wrap_get_netiw_info, netif_list);

  char *wifi = get_valid_iw(wifibuf);
  assert_null(wifi);
}

static void test_1_get_nat_if_ip(void **state)
{
  (void) state; /* unused */

  char *ip_buf = NULL;
  bool ret = get_nat_if_ip("nat_test", &ip_buf);

  assert_true(ret);
  assert_string_equal(ip_buf, "127.0.0.1");

  free(ip_buf);  
}

static void test_2_get_nat_if_ip(void **state)
{
  (void) state; /* unused */

  char *ip_buf = NULL;
  bool ret = get_nat_if_ip("wlan0", &ip_buf);

  assert_false(ret);

  free(ip_buf);  
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

int main(int argc, char *argv[])
{  
  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_1_is_iw_vlan),
    cmocka_unit_test(test_2_is_iw_vlan),
    cmocka_unit_test(test_3_is_iw_vlan),
    cmocka_unit_test(test_1_get_valid_iw),
    cmocka_unit_test(test_2_get_valid_iw),
    cmocka_unit_test(test_1_get_nat_if_ip),
    cmocka_unit_test(test_2_get_nat_if_ip),
    cmocka_unit_test(test_create_subnet_ifs)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
