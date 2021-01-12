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

  bool ret = ip_2_nbo("10.0.1.23", "255.255.255.0", &addr);
  assert_true(ret);
  assert_memory_equal(&addr, &subnet, sizeof(uint32_t));

  ret = ip_2_nbo("x.0.1.23", "255.255.255.0", &addr);
  assert_false(ret);
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
}

int main(int argc, char *argv[])
{  
  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_iface_exists),
    cmocka_unit_test(test_ip_2_nbo),
    cmocka_unit_test(test_get_if_mapper),
    cmocka_unit_test(test_put_if_mapper)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
