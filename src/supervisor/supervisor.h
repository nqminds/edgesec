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

#include <stdbool.h>
#include "../hostapd/config_generator.h"
#include "../utils/if.h"

#include "mac_mapper.h"

#define MAX_DOMAIN_RECEIVE_DATA 1024

/**
 * @brief Supervisor structure definition
 * 
 */
struct supervisor_context {
  hmap_mac_conn   *mac_mapper;                                /**< MAC mapper connection structure */
  hmap_if_conn    *if_mapper;                                 /**< WiFi subnet interface mapper */
  bool            allow_all_connections;                      /**< @c allow_all_connections Flag from @c struct app_config */
  char            hostapd_ctrl_if_path[MAX_OS_PATH_LEN];      /**< @c ctrl_interface param from @c struct hostapd_conf */
  char            wpa_passphrase[HOSTAPD_AP_SECRET_LEN];      /**< @c wpa_passphrase from @c struct hostapd_conf */
  char            nat_interface[IFNAMSIZ];                    /**< @c nat_interface param from @c struct app_config */
  char            subnet_mask[IP_LEN];                        /**< @c subnet_mask param from @c struct app_config */
  int             default_open_vlanid;                        /**< @c default_open_vlanid from @c struct app_config */
  UT_array        *config_ifinfo_array;                       /**< @c config_ifinfo_array from @c struct app_config */
};

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
 * @param sock The domain socket
 * @return true on success, false otherwise
 */
bool close_supervisor(int sock);

#endif