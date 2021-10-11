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
 * @file hostapd_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the hostapd service.
 */

#ifndef HOSTAPD_SERVICE_H
#define HOSTAPD_SERVICE_H

#include <sys/types.h>
#include <linux/if.h>
#include <stdbool.h>

#include "ap_config.h"
#include "../supervisor/supervisor_config.h"
#include "../radius/radius_server.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/if.h"

/**
 * @brief Runs the AP service
 * 
 * @param context The supervisor context structure
 * @param exec_ap Flag to execute the AP process
 * @param ap_callback_fn The callback for AP service
 * @return int 0 on success, -1 on failure
 */
int run_ap(struct supervisor_context *context, bool exec_ap, void *ap_callback_fn);

/**
 * @brief Closes (terminates) AP process
 * 
 * @param context The supervisor context structure
 * @return true success, false otherwise
 */
bool close_ap(struct supervisor_context *context);

/**
 * @brief Send a command to the AP service
 * 
 * @param socket_path The service UNIX domain path
 * @param cmd_str The command string
 * @param reply The reply
 * @return int 0 on success, -1 on failure
 */
int send_ap_command(char *socket_path, char *cmd_str, char **reply);

/**
 * @brief Deny ACL ADD AP command 
 * 
 * @param hconf AP config structure
 * @param mac_addr The mac address to add to deny list
 * @return int 0 on success, -1 on failure
 */
int denyacl_add_ap_command(struct apconf *hconf, char *mac_addr);

/**
 * @brief Deny ACL DEL AP command 
 * 
 * @param hconf AP config structure
 * @param mac_addr The mac address to remove from deny list
 * @return int 0 on success, -1 on failure
 */
int denyacl_del_ap_command(struct apconf *hconf, char *mac_addr);

/**
 * @brief Dissconnect and reconnect a MAC device from the AP
 * 
 * @param hconf AP config structure
 * @param mac_addr The mac address to disconnect
 * @return int 0 on success, -1 on failure
 */
int disconnect_ap_command(struct apconf *hconf, char *mac_addr);

/**
 * @brief Check if a station is registered on the AP
 * 
 * @param hconf AP config structure
 * @param mac_addr The mac address of the station
 * @return int 0 on success, -1 on failure
 */
int check_sta_ap_command(struct apconf *hconf, char *mac_addr);
#endif