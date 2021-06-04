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
 * @file network_commands.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the network commands.
 */

#ifndef NETWORK_COMMANDS_H
#define NETWORK_COMMANDS_H

#include <inttypes.h>
#include <stdbool.h>

/**
 * @brief Return a mac_conn_info for a given MAC address
 * 
 * @param mac_addr The input MAC adderss
 * @param mac_conn_arg The supervisor_context pointer
 * @return struct mac_conn_info 
 */
struct mac_conn_info get_mac_conn_cmd(uint8_t mac_addr[], void *mac_conn_arg);

/**
 * @brief ACCEPT_MAC command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param vlanid The VLAN ID
 * @return int 0 on success, -1 on failure
 */
int accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr, int vlanid);

/**
 * @brief DENY_MAC command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @return int 0 on success, -1 on failure
 */
int deny_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief ADD_NAT command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @return int 0 on success, -1 on failure
 */
int add_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief REMOVE_NAT command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @return int 0 on success, -1 on failure
 */
int remove_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief ASSIGN_PSK command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param pass The password
 * @param pass_len The password length
 * @return int 0 on success, -1 on failure
 */
int assign_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *pass, int pass_len);

/**
 * @brief SET_IP command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param ip_addr The IP address
 * @param add if add = true then add IP to MAC entry, otherwise remove
 * @return int 0 on success, -1 on failure
 */
int set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *ip_addr, bool add);

/**
 * @brief ADD_BRIDGE command
 * 
 * @param context The supervisor structure instance
 * @param left_mac_addr The left MAC address
 * @param right_mac_addr The right MAC address
 * @return int 0 on success, -1 on failure
 */
int add_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr);

/**
 * @brief REMOVE_BRIDGE command
 * 
 * @param context The supervisor structure instance
 * @param left_mac_addr The left MAC address
 * @param right_mac_addr The right MAC address
 * @return int 0 on success, -1 on failure
 */
int remove_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr);

/**
 * @brief SET_FINGERPRINT command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address string
 * @param protocol The protocol string
 * @param fingerprint The fingerprint string
 * @return int 0 on success, -1 on failure
 */
int set_fingerprint_cmd(struct supervisor_context *context, char *mac_addr, char *protocol,
                        char *fingerprint);

#endif
