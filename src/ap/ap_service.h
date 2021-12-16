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

#define STA_AP_COMMAND                  "STA"

#define GENERIC_AP_COMMAND_OK_REPLY     "OK"
#define GENERIC_AP_COMMAND_FAIL_REPLY   "FAIL"

#define PING_AP_COMMAND                 "PING"
#define PING_AP_COMMAND_REPLY           "PONG"

#define DENYACL_ADD_COMMAND             "DENY_ACL ADD_MAC"
#define DENYACL_DEL_COMMAND             "DENY_ACL DEL_MAC"

/**
 * @brief Runs the AP service
 * 
 * @param context The supervisor context structure
 * @param exec_ap Flag to execute/signal the AP process
 * @param generate_ssid Flag to generate the SSID for AP
 * @param ap_callback_fn The callback for AP service
 * @return int 0 on success, -1 on failure
 */
int run_ap(struct supervisor_context *context, bool exec_ap, bool generate_ssid,
           void *ap_callback_fn);

/**
 * @brief Closes (terminates) AP process
 * 
 * @param context The supervisor context structure
 * @return true success, false otherwise
 */
bool close_ap(struct supervisor_context *context);

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