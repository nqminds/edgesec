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
 * @file supervisor.c
 * @author Alexandru Mereacre 
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
void ap_service_callback(struct supervisor_context *context, uint8_t mac_addr[], enum AP_CONNECTION_STATUS status);

/**
 * @brief Executes the supervisor service
 * 
 * @param server_path The domain socket path
 * @param context The supervisor structure
 * @return int The domain socket
 */
int run_supervisor(char *server_path, struct supervisor_context *context);

/**
 * @brief Closes the supervisor service
 * 
 * @param context The supervisor structure
 * @return true on success, false otherwise
 */
void close_supervisor(struct supervisor_context *context);

#endif