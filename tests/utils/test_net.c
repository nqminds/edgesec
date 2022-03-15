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
#include "utils/net.h"
#include "utils/utarray.h"

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

static void test_ip4_2_buf(void **state)
{
  (void) state; /* unused */
  char *ip = "10.0.0.23", *ip1 = "x.168.1.12";
  uint8_t buf[IP_ALEN];

  assert_int_equal(ip4_2_buf(ip, buf), 0);
  assert_int_equal(buf[0], 10);
  assert_int_equal(buf[1], 0);
  assert_int_equal(buf[2], 0);
  assert_int_equal(buf[3], 23);

  assert_int_equal(ip4_2_buf(ip1, buf), -1);
}

static void test_validate_ipv4_string(void **state)
{
  (void) state;

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


static void test_get_ip_host(void **state)
{
  (void) state;
  uint32_t host;

  assert_int_equal(get_ip_host("10.0.1.2", "255.255.255.0", &host), 0);
  assert_int_equal(host, 2);

  assert_int_equal(get_ip_host("10.0.1.0", "255.255.255.0", &host), 0);
  assert_int_equal(host, 0);

  assert_int_equal(get_ip_host("10.0.0.255", "255.255.255.0", &host), 0);
  assert_int_equal(host, 255);

  assert_int_equal(get_ip_host("10.0.10.2", "255.255.0.0", &host), 0);
  assert_int_equal(host, 2562);
}

int main(int argc, char *argv[])
{  
  (void) argc;
  (void) argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_ip_2_nbo),
    cmocka_unit_test(test_ip4_2_buf),
    cmocka_unit_test(test_validate_ipv4_string),
    cmocka_unit_test(test_get_ip_host)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
