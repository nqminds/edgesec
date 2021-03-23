/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file cmd_processor.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the command processor functions.
 */

#ifndef CMD_PROCESSOR_H
#define CMD_PROCESSOR_H

#include <sys/types.h>
#include <stdbool.h>

#include "../utils/utarray.h"

#include "supervisor_config.h"

#define CMD_DELIMITER   		0x20

#define CMD_PING        		"PING_SUPERVISOR"
#define CMD_HOSTAPD_CTRLIF      "HOSTAPD_IF"
#define CMD_ACCEPT_MAC			"ACCEPT_MAC"
#define CMD_DENY_MAC			"DENY_MAC"
#define CMD_ADD_NAT				"ADD_NAT"
#define CMD_REMOVE_NAT			"REMOVE_NAT"
#define CMD_ASSIGN_PSK			"ASSIGN_PSK"
#define CMD_GET_MAP				"GET_MAP"
#define CMD_GET_ALL				"GET_ALL"
#define CMD_SAVE_ALL			"SAVE_ALL"
#define CMD_SET_IP				"SET_IP"
#define CMD_ADD_BRIDGE			"ADD_BRIDGE"
#define CMD_REMOVE_BRIDGE		"REMOVE_BRIDGE"
#define CMD_GET_BRIDGES		    "GET_BRIDGES"

#define OK_REPLY                "OK"
#define FAIL_REPLY              "FAIL"

typedef ssize_t (*process_cmd_fn)(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the domain command string
 * 
 * @param domain_buffer The domain command string
 * @param domain_buffer_len The domain command string length
 * @param cmd_arr The processed command array
 * @return true on success, false otherwise
 */
bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len, UT_array *cmd_arr);

/**
 * @brief Processes the PING command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_ping_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the HOSTAPD_IF command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_hostapd_ctrlif_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the ACCEPT_MAC command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_accept_mac_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the DENY_MAC command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_deny_mac_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the ADD_NAT command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_add_nat_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the REMOVE_NAT command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_remove_nat_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the ASSIGN_PSK command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_assign_psk_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the GET_MAP command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_get_map_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the GET_ALL command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_get_all_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the SET_IP command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_set_ip_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the ADD_BRIDGE command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_add_bridge_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the REMOVE_BRIDGE command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_remove_bridge_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the GET_BRIDGES command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_get_bridges_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Get the command function pointer
 * 
 * @param cmd The command string
 * @return process_cmd_fn The returned function pointer
 */
process_cmd_fn get_command_function(char *cmd);
#endif