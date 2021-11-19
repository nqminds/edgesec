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

#define MDNS_OPT_STRING    ":i:q:f:x:z:dvh46"
#define MDNS_USAGE_STRING  "\t%s [-d] [-h] [-v] [-i interface] [-q domain]" \
                              "[-f filter] [-x command] [-z delimiter]\n"
extern const char* const mdns_description_string;

#define MDNS_OPT_DEFS      "\t-q domain\t The UNIX domain path\n" \
                              "\t-x command\t The UNIX domain command\n" \
                              "\t-z delimiter\t The UNIX domain command delimiter\n" \
                              "\t-i interface\t The capture interface name\n" \
                              "\t-f filter\t The capture filter expression\n" \
                              "\t-4 \t\t Reflect IP4\n" \
                              "\t-6 \t\t Reflect IP6\n" \
                              "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n" \
                              "\t-h\t\t Show help\n" \
                              "\t-v\t\t Show app version\n\n"

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
  char domain_server_path[MAX_OS_PATH_LEN];                   /**< Specifies the path to the UNIX domain socket server */
  char domain_command[MAX_SUPERVISOR_CMD_SIZE];               /**< Specifies the UNIX domain command */
  char domain_delim;                                          /**< Specifies the UNIX domain command delimiter */
  char capture_interface[MAX_CAPIF_LIST_SIZE];                /**< The capture interface name(s) (if multiple delimited by space) */
  char filter[MAX_FILTER_SIZE];                               /**< Specifies the filter expression or pcap lib */
  bool reflect_ip4;                                           /**< Reflect mDNS IP4 addresses. */
  bool reflect_ip6;                                           /**< Reflect mDNS IP6 addresses. */
};

/**
 * @brief Translate a mDNS process option to a config structure value
 * 
 * @param key mDNS process option key
 * @param opt mDNS process option value
 * @param config The config structure
 * @return int 0 on success, -1 on error and 1 for an unknown option key
 */
int mdns_opt2config(char key, char *value, struct mdns_conf *config);

/**
 * @brief Transforms a config structure to opt string array
 * 
 * @param config The config structure
 * @return char** the opt string array, NULL on failure
 */
char** mdns_config2opt(struct mdns_conf *config);

/**
 * @brief Free opt string array
 * 
 * @param opt_str Opt string array
 */
void mdns_freeopt(char **opt_str);

#endif