/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file firewall_service.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the firewall service commands.
 */

#ifndef FIREWALL_SERVICE_H
#define FIREWALL_SERVICE_H

#include <inttypes.h>
#include <stdbool.h>

#include "../supervisor/supervisor_config.h"
#include "../utils/utarray.h"
#include "../utils/hashmap.h"
#include "../utils/iface_mapper.h"

#include "firewall_config.h"

/**
 * @brief Initialises the firewall service context
 *
 * @param if_mapper The WiFi subnet to interface mapper
 * @param vlan_mapper The WiFi VLAN to interface mapper
 * @param hmap_bin_paths The Mapper for paths to systems binaries
 * @param config_ifinfo_array The @c config_ifinfo_array from @c struct
 * app_config
 * @param nat_interface The nat interface string
 * @param exec_firewall if true runs the firewall system commands
 * @param path The firewall bin path
 * @return struct fwctx* on success, NULL on failure
 */
struct fwctx *fw_init_context(hmap_if_conn *if_mapper,
                              hmap_vlan_conn *vlan_mapper,
                              hmap_str_keychar *hmap_bin_paths,
                              UT_array *config_ifinfo_array, char *nat_bridge,
                              char *nat_interface, bool exec_firewall,
                              char *path);

/**
 * @brief Frees the firewall service context
 *
 * @param context The firewall context
 */
void fw_free_context(struct fwctx *context);

/**
 * @brief Adds NAT rule to an IP
 *
 * @param context The firewall context
 * @param ip_addr The IP address string
 * @return 0 on sucess, -1 on failure
 */
int fw_add_nat(struct fwctx *context, char *ip_addr);

/**
 * @brief Removes NAT rule to an IP
 *
 * @param context The firewall context
 * @param ip_addr The IP address string
 * @return 0 on sucess, -1 on failure
 */
int fw_remove_nat(struct fwctx *context, char *ip_addr);

/**
 * @brief Adds bridge rule for two IPs
 *
 * @param context The firewall context
 * @param ip_addr_left The IP address string left
 * @param ip_addr_right The IP address string right
 * @return 0 on sucess, -1 on failure
 */
int fw_add_bridge(struct fwctx *context, char *ip_addr_left,
                  char *ip_addr_right);

/**
 * @brief Removes bridge rule for two IPs
 *
 * @param context The firewall context
 * @param ip_addr_left The IP address string left
 * @param ip_addr_right The IP address string right
 * @return 0 on sucess, -1 on failure
 */
int fw_remove_bridge(struct fwctx *context, char *ip_addr_left,
                     char *ip_addr_right);

/**
 * @brief Set the ip forward os system param
 *
 * @return int 0 on success, -1 on failure
 */

int fw_set_ip_forward(void);

#endif
