/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
 *                                                                          *
 * This file is part of EDGESec.                                            *
 *                                                                          *
 *   EDGESec is free software: you can redistribute it and/or modify it     *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   EDGESec is distributed in the hope that it will be useful,             *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with EDGESec. If not, see <http://www.gnu.org/licenses/>.*
 ****************************************************************************/

/**
 * @file dns_config.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of dns service configuration utilities.
 */
#ifndef DNS_CONFIG_H
#define DNS_CONFIG_H

#include "../utils/utarray.h"
#include "../capture/capture_config.h"

#define MDNS_MAX_OPT       26

#define MDNS_OPT_CONFIG    "-c"
#define MDNS_OPT_STRING    ":c:dvh"
#define MDNS_USAGE_STRING  "\t%s [-d] [-h] [-v] [-c config]"

#define MDNS_OPT_DEFS      "\t-q domain\t The UNIX domain path\n" \
                              "\t-c config\t The config file path\n" \
                              "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n" \
                              "\t-h\t\t Show help\n" \
                              "\t-v\t\t Show app version\n\n"


#define MDNS_DESCRIPTION "--" \
  "NquiringMinds EDGESEC mdns forwarder.\n" \
  "\n" \
  "Forwards and captures EDGESEC mDNS network traffic for each connected device.\n" \
  "The resulting captured mDNS traffic is forwarded across subnets and bridge commands are issued accordingly.\n\n"

/**
 * @brief The dns configuration structures.
 * 
 */
struct dns_conf {
  UT_array *server_array;                      /**< The array including the DNS servers IP addresses. */
};

/**
 * @brief The mDNS configuration structures.
 * 
 */
struct mdns_conf {
  char mdns_bin_path[MAX_OS_PATH_LEN];                        /**< Path to the mDNS binary */
  char filter[MAX_FILTER_SIZE];                               /**< Specifies the filter expression or pcap lib */
  bool reflect_ip4;                                           /**< Reflect mDNS IP4 addresses. */
  bool reflect_ip6;                                           /**< Reflect mDNS IP6 addresses. */
};

#endif