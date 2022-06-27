/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file dns_config.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of dns service configuration utilities.
 */
#ifndef DNS_CONFIG_H
#define DNS_CONFIG_H

#include "../utils/utarray.h"
#include "../capture/capture_config.h"

#define MDNS_MAX_OPT 26

#define MDNS_OPT_CONFIG "-c"
#define MDNS_OPT_STRING ":c:dvh"
#define MDNS_USAGE_STRING "\t%s [-d] [-h] [-v] [-c config]"

#define MDNS_OPT_DEFS                                                          \
  "\t-c config\t The config file path\n"                                       \
  "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n"               \
  "\t-h\t\t Show help\n"                                                       \
  "\t-v\t\t Show app version\n\n"

#define MDNS_DESCRIPTION                                                       \
  "--"                                                                         \
  "NquiringMinds EDGESEC mdns forwarder.\n"                                    \
  "\n"                                                                         \
  "Forwards and captures EDGESEC mDNS network traffic for each connected "     \
  "device.\n"                                                                  \
  "The resulting captured mDNS traffic is forwarded across subnets and "       \
  "bridge commands are issued accordingly.\n\n"

/**
 * @brief The dns configuration structures.
 *
 */
struct dns_conf {
  UT_array
      *server_array; /**< The array including the DNS servers IP addresses. */
};

/**
 * @brief The mDNS configuration structures.
 *
 */
struct mdns_conf {
  char filter[MAX_FILTER_SIZE]; /**< Specifies the filter expression or pcap lib
                                 */
  bool reflect_ip4;             /**< Reflect mDNS IP4 addresses. */
  bool reflect_ip6;             /**< Reflect mDNS IP6 addresses. */
};

#endif
