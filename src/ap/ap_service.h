/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file ap_service.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the ap service.
 *
 * Defines the functions to start and stop the acces point service (AP). It also
 * defines auxiliary commands to manage the acces control list for stations
 * connected to the AP.
 */

#ifndef HOSTAPD_SERVICE_H
#define HOSTAPD_SERVICE_H

#include <sys/types.h>
#include <stdbool.h>

#include "ap_config.h"
#include "../supervisor/supervisor_config.h"
#include "../radius/radius_server.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/iface.h"

#define STA_AP_COMMAND                                                         \
  "STA" /* Command name to check if a station is registered */

#define GENERIC_AP_COMMAND_OK_REPLY "OK" /* The command response on succes */
#define GENERIC_AP_COMMAND_FAIL_REPLY                                          \
  "FAIL" /* The command response on failure */

#define PING_AP_COMMAND "PING" /* Command name to ping the hostapd daemon */
#define PING_AP_COMMAND_REPLY "PONG" /* Reply to the ping command */

#define DENYACL_ADD_COMMAND                                                    \
  "DENY_ACL ADD_MAC" /* Command name to add a station to the deny ACL */
#define DENYACL_DEL_COMMAND                                                    \
  "DENY_ACL DEL_MAC" /* Command name to remove a station from the deny ACL */

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
 * @brief Disconnect and reconnect a MAC device from the AP
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
