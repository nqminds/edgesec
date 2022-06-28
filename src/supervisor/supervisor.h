/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the supervisor service.
 */

#ifndef SUPERVISOR_H
#define SUPERVISOR_H

#include "supervisor_config.h"

/**
 * @brief Return a mac_conn_info for a given MAC address
 *
 * @param mac_addr The input MAC adderss
 * @param mac_conn_arg The supervisor_context pointer
 * @return struct mac_conn_info
 */
struct mac_conn_info get_mac_conn_cmd(uint8_t mac_addr[], void *mac_conn_arg);

/**
 * @brief The AP service callback
 *
 * @param context The supervisor context
 * @param mac_addr The STA mac address
 * @param status The STA connection status
 * @return 0 on success, -1 on failure
 */
void ap_service_callback(struct supervisor_context *context, uint8_t mac_addr[],
                         enum AP_CONNECTION_STATUS status);

/**
 * @brief Executes the supervisor service
 *
 * @param server_path The domain socket path
 * @param port The UDP port
 * @param context The supervisor structure
 * @return int The domain socket
 */
int run_supervisor(char *server_path, unsigned int port,
                   struct supervisor_context *context);

/**
 * @brief Closes the supervisor service
 *
 * @param context The supervisor structure
 * @return true on success, false otherwise
 */
void close_supervisor(struct supervisor_context *context);

#endif
