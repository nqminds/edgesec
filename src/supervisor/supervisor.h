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
 * @brief Returns the identity access control
 *
 * @param identity The identity array
 * @param identity_len The identity array size
 * @param mac_conn_arg The supervisor_context pointer
 * @param iinfo The returned identity info structure
 * @return 0 for success, -1 for error
 */
int get_identity_ac(const uint8_t *identity, size_t identity_len,
                                      void *mac_conn_arg, struct identity_info *iinfo);

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
