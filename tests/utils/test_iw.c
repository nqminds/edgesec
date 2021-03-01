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
  if (!wiphy) return false;

  return true;
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
  assert_false(ret);
}

// static void test_2_is_iw_vlan(void **state)
// {
//   (void) state; /* unused */

//   UT_array *netif_list = NULL;
//   netiw_info_t el;
//   utarray_new(netif_list, &netiw_info_icd);

//   expect_string(__wrap_iface_exists, ifname, "wlan1");
//   will_return(__wrap_iface_exists, true);

//   strcpy(el.ifname, "wlan0");
//   el.wiphy = 0;
//   utarray_push_back(netif_list, &el);

//   strcpy(el.ifname, "wlan1");
//   el.wiphy = 1;
//   utarray_push_back(netif_list, &el);

//   strcpy(el.ifname, "wlan2");
//   el.wiphy = 2;
//   utarray_push_back(netif_list, &el);

//   will_return(__wrap_get_netiw_info, netif_list);

//   bool ret = is_iw_vlan("wlan1");
//   assert_false(ret);
// }

static void test_3_is_iw_vlan(void **state)
{
  (void) state; /* unused */

  expect_any(__wrap_iface_exists, ifname);
  will_return(__wrap_iface_exists, false);

  bool ret = is_iw_vlan(NULL);
  assert_false(ret);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_1_is_iw_vlan)//,
    // cmocka_unit_test(test_2_is_iw_vlan),
    // cmocka_unit_test(test_3_is_iw_vlan)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
