/**
 * @file
 * @author Alois Klink
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief Tests for dhcp_config_utils.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

#include "./dhcp/dhcp_config.h"
#include "./dhcp/dhcp_config_utils.h"

#define TOO_LARGE_IP_ADDRESS "192.0.0.00000000000001"

static void test_get_config_dhcpinfo(void **state) {
  (void)state;

  {
    // should work with valid data
    config_dhcpinfo_t dhcp_info = {0};
    assert_true(get_config_dhcpinfo("1,10.0.0.2,10.0.0.254,255.255.255.0,24h",
                                    &dhcp_info));
    assert_int_equal(dhcp_info.vlanid, 1);
    assert_string_equal(dhcp_info.ip_addr_low, "10.0.0.2");
    assert_string_equal(dhcp_info.ip_addr_upp, "10.0.0.254");
    assert_string_equal(dhcp_info.subnet_mask, "255.255.255.0");
    assert_string_equal(dhcp_info.lease_time, "24h");
  }

  {
    // should return false when data is invalid
    config_dhcpinfo_t dhcp_info = {0};

    // missing lease_time data
    assert_false(
        get_config_dhcpinfo("1,10.0.0.2,10.0.0.254,255.255.255.0", &dhcp_info));

    // vlanid greater than UINTMAX_T
    assert_false(get_config_dhcpinfo(
        "8589934592,10.0.0.2,10.0.0.254,255.255.255.0", &dhcp_info));

    // ip_addr_upp larger than sizeof(dhcp_info.ip_addr_upp) bytes
    char too_large_ip[] = TOO_LARGE_IP_ADDRESS;
    // one byte too large due to NUL-terminator
    assert_int_equal(strlen(too_large_ip), sizeof(dhcp_info.ip_addr_upp));
    assert_false(get_config_dhcpinfo("8589934592,10.0.0.2," TOO_LARGE_IP_ADDRESS
                                     ",255.255.255.0",
                                     &dhcp_info));
  }
}

int main(int argc, char *argv[]) {
  (void)argc; /* unused */
  (void)argv; /* unused */
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_get_config_dhcpinfo)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
