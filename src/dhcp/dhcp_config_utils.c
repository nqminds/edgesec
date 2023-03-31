#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include "../utils/log.h"
#include "../utils/net.h"

#include "./dhcp_config_utils.h"

#define CAT(a, ...) PRIMITIVE_CAT(a, __VA_ARGS__)
#define PRIMITIVE_CAT(a, ...) a##__VA_ARGS__

/**
 * Decrements the given number using the forbidden magicks of the C
 * preprocessor.
 *
 * Currently only works for numbers up to 22, but you can add more defines
 * for more numbers if you want.
 *
 * Boost has a `preprocessor` library that can do this too,
 * see https://www.boost.org/doc/libs/1_81_0/libs/preprocessor/doc/index.html.
 *
 * @author Paul Fultz II https://github.com/pfultz2/Cloak
 * @copyright SPDX-FileCopyrightText: Copyright (c) 2015 Paul Fultz II
 * SPDX-License-Identifier: BSL-1.0
 * @remark
 * Adapted from https://github.com/pfultz2/Cloak/blob/master/cloak.h
 */
#define DEC(x) PRIMITIVE_CAT(DEC_, x)
#define DEC_0 0
#define DEC_1 0
#define DEC_2 1
#define DEC_3 2
#define DEC_4 3
#define DEC_5 4
#define DEC_6 5
#define DEC_7 6
#define DEC_8 7
#define DEC_9 8
#define DEC_10 9
#define DEC_11 10
#define DEC_12 11
#define DEC_13 12
#define DEC_14 13
#define DEC_15 14
#define DEC_16 15
#define DEC_17 16
#define DEC_18 17
#define DEC_19 18
#define DEC_20 19
#define DEC_21 20
#define DEC_22 21

#define STR(x) #x
#define XSTR(s) STR(s)

/**
 * scanf() specifier to read an IPv4 address in dot-separated decimal notation.
 */
#define SCANF_IPv4_STRING "%" XSTR(DEC(OS_INET_ADDRSTRLEN)) "[0123456789.]"

/**
 * scanf() specifier to read a `dnsmasq` dhcp lease time (i.e. `24h`)
 */
#define SCANF_DHCP_LEASE_TIME_STRING "%" XSTR(DEC(DHCP_LEASE_TIME_SIZE)) "s"

bool get_config_dhcpinfo(const char *info, config_dhcpinfo_t *el) {
  config_dhcpinfo_t scanf_results = {0};

  int substrings =
      sscanf(info,
             "%d," SCANF_IPv4_STRING "," SCANF_IPv4_STRING "," SCANF_IPv4_STRING
             "," SCANF_DHCP_LEASE_TIME_STRING,
             &scanf_results.vlanid, scanf_results.ip_addr_low,
             scanf_results.ip_addr_upp, scanf_results.subnet_mask,
             scanf_results.lease_time);

  if (substrings < 5) {
    log_error("get_config_dhcpinfo: Expected 5 comma-separated substrings but "
              "got %d in string %s",
              substrings, info);
    return false;
  }

  *el = scanf_results;

  return true;
}
