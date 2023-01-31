/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the ap service.
 *
 * Defines the functions to start and stop the acces point service (AP). It also
 * defines auxiliary commands to manage the acces control list for stations
 * connected to the AP.
 */

#ifndef HOSTAPD_SERVICE_H
#define HOSTAPD_SERVICE_H

#include <stdbool.h>
#include <sys/types.h>

#include "../radius/radius_server.h"
#include "../supervisor/supervisor_config.h"
#include "../utils/allocs.h"
#include "../utils/iface.h"
#include "../utils/os.h"
#include "ap_config.h"

#define ATTACH_AP_COMMAND "ATTACH"

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

/** Type of callback for AP service in run_ap()*/
typedef void (*ap_service_fn)(struct supervisor_context *context,
                              uint8_t mac_addr[],
                              enum AP_CONNECTION_STATUS status);

/** Structure containing @p ap_callback_fn callback pointer for run_ap() */
struct run_ap_callback_fn_struct {
  /** The callback for the AP service. */
  ap_service_fn ap_service_fn;
};

/**
 * @brief Runs the AP service
 *
 * @param context The supervisor context structure
 * @param exec_ap Flag to execute/signal the AP process
 * @param generate_ssid Flag to generate the SSID for AP
 * @param[in] ap_callback_fn A stuct containing the callback for AP service
 * @return int 0 on success, -1 on failure
 */
int run_ap(struct supervisor_context *context, bool exec_ap, bool generate_ssid,
           struct run_ap_callback_fn_struct *ap_callback_fn);

/**
 * @brief Closes (terminates) AP process
 *
 * @param context The supervisor context structure
 * @return true success, false otherwise
 */
bool close_ap(struct supervisor_context *context);

/**
 * @brief Pings the hostapd daemon.
 *
 * @param hconf AP config structure
 * @retval  `0` if the hostapd daemon responded okay.
 * @retval `-1` if the hostapd daemon didn't respond or had an invalid response.
 */
int ping_ap_command(struct apconf *hconf);

/**
 * @brief Deny ACL ADD AP command
 *
 * @param hconf AP config structure
 * @param mac_addr The mac address to add to deny list
 * @return int 0 on success, -1 on failure
 */
int denyacl_add_ap_command(struct apconf *hconf, const char *mac_addr);

/**
 * @brief Deny ACL DEL AP command
 *
 * @param hconf AP config structure
 * @param mac_addr The mac address to remove from deny list
 * @return int 0 on success, -1 on failure
 */
int denyacl_del_ap_command(struct apconf *hconf, const char *mac_addr);

/**
 * @brief Disconnect and reconnect a MAC device from the AP
 *
 * @param hconf AP config structure
 * @param mac_addr The mac address to disconnect
 * @return int 0 on success, -1 on failure
 */
int disconnect_ap_command(struct apconf *hconf, const char *mac_addr);

/**
 * @brief Check if a station is registered on the AP
 *
 * @param hconf AP config structure
 * @param mac_addr The mac address of the station
 * @return int 0 on success, -1 on failure
 */
int check_sta_ap_command(struct apconf *hconf, const char *mac_addr);
#endif
