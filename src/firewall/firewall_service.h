/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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

#include "../utils/iptables.h"

#include "firewall_config.h"

/**
 * @brief Initialises the firewall service context
 * 
 * @param if_mapper The WiFi subnet to interface mapper
 * @param vlan_mapper The WiFi VLAN to interface mapper
 * @param hmap_bin_paths The Mapper for paths to systems binaries
 * @param config_ifinfo_array The @c config_ifinfo_array from @c struct app_config
 * @param nat_interface The nat interface string
 * @param exec_firewall if true runs the firewall system commands
 * @return struct fwctx* on success, NULL on failure
 */
struct fwctx* fw_init_context(hmap_if_conn *if_mapper,
                              hmap_vlan_conn  *vlan_mapper,
                              hmap_str_keychar *hmap_bin_paths,
                              UT_array *config_ifinfo_array,
                              char *nat_interface,
                              bool exec_firewall);


/**
 * @brief Frees the firewall service context
 * 
 * @param context The firewall context
 */
void fw_free_context(struct fwctx* context);

/**
 * @brief Adds NAT rule to an IP
 * 
 * @param context The firewall context
 * @param ip_addr The IP address string
 * @return 0 on sucess, -1 on failure
 */
int fw_add_nat(struct fwctx* context, char *ip_addr);

/**
 * @brief Removes NAT rule to an IP
 * 
 * @param context The firewall context
 * @param ip_addr The IP address string
 * @return 0 on sucess, -1 on failure
 */
int fw_remove_nat(struct fwctx* context, char *ip_addr);

/**
 * @brief Adds bridge rule for two IPs
 * 
 * @param context The firewall context
 * @param ip_addr_left The IP address string left
 * @param ip_addr_right The IP address string right
 * @return 0 on sucess, -1 on failure
 */
int fw_add_bridge(struct fwctx* context, char *ip_addr_left, char *ip_addr_right);

/**
 * @brief Removes bridge rule for two IPs
 * 
 * @param context The firewall context
 * @param ip_addr_left The IP address string left
 * @param ip_addr_right The IP address string right
 * @return 0 on sucess, -1 on failure
 */
int fw_remove_bridge(struct fwctx* context, char *ip_addr_left, char *ip_addr_right);

/**
 * @brief Set the ip forward os system param
 * 
 * @return int 0 on success, -1 on failure
 */

int fw_set_ip_forward(void);

#endif