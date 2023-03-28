/**
 * @file
 * @author Alois Klink
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief Functions that help work with DHCP Configuration structures.
 */
#ifndef DHCP_CONFIG_UTILS_H
#define DHCP_CONFIG_UTILS_H

#include <stdbool.h>

#include "./dhcp_config.h"

/**
 * @brief Creates a `config_dhcpinfo_t` from a string.
 *
 * @param[in] info - The string to parse.
 * The format of this string is a comma-separated value line of:
 * `<vlanid>,<ip_addr_low>,<ip_addr_upp>,<subnet_mask>,<lease_time>`
 *
 * `vlanid` must be a decimal integer.
 *
 * All other parameters are passed as a `dhcp-range` option to dnsmasq,
 * see [`man dnsmasq(8)`](https://linux.die.net/man/8/dnsmasq).
 *
 * For example: `0,10.0.0.2,10.0.0.254,255.255.255.0,24h`.
 *
 * @param[out] el - The parsed dhcp info.
 * @retval true  On success.
 * @retval false On failure.
 */
bool get_config_dhcpinfo(const char *info, config_dhcpinfo_t *el);

#endif /* DHCP_CONFIG_UTILS_H */
