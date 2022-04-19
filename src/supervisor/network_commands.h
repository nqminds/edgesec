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

#define TICKET_PASSPHRASE_SIZE 16
#define TICKET_TIMEOUT 60 // In seconds

#include "supervisor_config.h"
#include "../ap/ap_config.h"

/**
 * @brief Save a MAC entry into the mapper
 *
 * @param The supervisor context
 * @param The MAc connection structure
 *
 * @return true on success, false on failure
 */
bool save_mac_mapper(struct supervisor_context *context, struct mac_conn conn);

/**
 * @brief Frees an allocated ticket
 *
 * @param The supervisor context
 */
void free_ticket(struct supervisor_context *context);

/**
 * @brief ACCEPT_MAC command
 *
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param vlanid The VLAN ID
 * @return int 0 on success, -1 on failure
 */
int accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr,
                   int vlanid);

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
 * @brief ADD_BRIDGE command (MAC address input)
 *
 * @param context The supervisor structure instance
 * @param left_mac_addr The left MAC address
 * @param right_mac_addr The right MAC address
 * @return int 0 on success, -1 on failure
 */
int add_bridge_mac_cmd(struct supervisor_context *context,
                       uint8_t *left_mac_addr, uint8_t *right_mac_addr);

/**
 * @brief ADD_BRIDGE command (IP address input)
 *
 * @param context The supervisor structure instance
 * @param left_ip_addr The left IP address
 * @param right_ip_addr The right IP address
 * @return int 0 on success, -1 on failure
 */
int add_bridge_ip_cmd(struct supervisor_context *context, char *left_ip_addr,
                      char *right_ip_addr);

/**
 * @brief REMOVE_BRIDGE command
 *
 * @param context The supervisor structure instance
 * @param left_mac_addr The left MAC address
 * @param right_mac_addr The right MAC address
 * @return int 0 on success, -1 on failure
 */
int remove_bridge_cmd(struct supervisor_context *context,
                      uint8_t *left_mac_addr, uint8_t *right_mac_addr);

/**
 * @brief CLEAR_BRIDGES command
 *
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @return int 0 on success, -1 on failure
 */
int clear_bridges_cmd(struct supervisor_context *context,
                      uint8_t *left_mac_addr);

/**
 * @brief REGISTER_TICKET command
 *
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address string
 * @param label The label string
 * @param vlanid The VLAN ID
 * @return char* passphrase string, NULL on failure
 */
uint8_t *register_ticket_cmd(struct supervisor_context *context,
                             uint8_t *mac_addr, char *label, int vlanid);

/**
 * @brief CLEAR_PSK command
 *
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address string
 * @return 0 on success, -1 on failure
 */
int clear_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief Add an IP to NAT
 *
 * @param context The supervisor structure instance
 * @param ip_addr The IP address string
 * @return 0 on success, -1 on failure
 */
int add_nat_ip(struct supervisor_context *context, char *ip_addr);

/**
 * @brief Remove an IP to NAT
 *
 * @param context The supervisor structure instance
 * @param ip_addr The IP address string
 * @return 0 on success, -1 on failure
 */
int remove_nat_ip(struct supervisor_context *context, char *ip_addr);

/**
 * @brief Add an IP bridge
 *
 * @param context The supervisor structure instance
 * @param ip_addr_left The left IP address string
 * @param ip_addr_right The right IP address string
 * @return 0 on success, -1 on failure
 */
int add_bridge_ip(struct supervisor_context *context, char *ip_addr_left,
                  char *ip_addr_right);

/**
 * @brief Deletes an IP bridge
 *
 * @param context The supervisor structure instance
 * @param ip_addr_left The left IP address string
 * @param ip_addr_right The right IP address string
 * @return 0 on success, -1 on failure
 */
int delete_bridge_ip(struct supervisor_context *context, char *ip_addr_left,
                     char *ip_addr_right);
#endif
