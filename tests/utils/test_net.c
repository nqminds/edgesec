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


int main(int argc, char *argv[])
{  
  (void) argc;
  (void) argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_ip_2_nbo),
    cmocka_unit_test(test_ip4_2_buf),
    cmocka_unit_test(test_validate_ipv4_string)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
