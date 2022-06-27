/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of dhcp configuration structures.
 */
#ifndef DHCP_CONFIG_H
#define DHCP_CONFIG_H

#include <linux/if.h>

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/net.h"
#include "../utils/utarray.h"

#define DHCP_LEASE_TIME_SIZE 10

/**
 * @brief The dhcp mapping structure
 *
 */
typedef struct config_dhcpinfo_t {
  int vlanid;                            /**< Interface VLAN ID */
  char ip_addr_low[OS_INET_ADDRSTRLEN];  /**< Interface string IP address lower
                                            bound */
  char ip_addr_upp[OS_INET_ADDRSTRLEN];  /**< Interface string IP address upper
                                            bound */
  char subnet_mask[OS_INET_ADDRSTRLEN];  /**< Interface string IP subnet mask */
  char lease_time[DHCP_LEASE_TIME_SIZE]; /**< Interface lease time string */
} config_dhcpinfo_t;

/**
 * @brief The dhcp configuration structures.
 *
 */
struct dhcp_conf {
  char dhcp_bin_path[MAX_OS_PATH_LEN];    /**< The dhcp bin path string */
  char dhcp_conf_path[MAX_OS_PATH_LEN];   /**< The dhcp config path string */
  char dhcp_script_path[MAX_OS_PATH_LEN]; /**< The dhcp executable script path
                                             string */
  char dhcp_leasefile_path[MAX_OS_PATH_LEN]; /**< The dhcp lease file path
                                                string */
  char bridge_prefix[IFNAMSIZ];    /**< The bridge interface prefix. */
  char wifi_interface[IFNAMSIZ];   /**< The wifi interface. */
  UT_array *config_dhcpinfo_array; /**< Array containg the mapping between VLAN
                                      ID sand IP address range. */
};
#endif
