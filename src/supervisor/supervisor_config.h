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
 * @file supervisor_config.c
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the supervisor service structure.
 */

#ifndef SUPERVISOR_CONFIG_H
#define SUPERVISOR_CONFIG_H

#include <stdbool.h>
#include <sqlite3.h>

#include "../ap/ap_config.h"
#include "../utils/if.h"
#include "../capture/capture_config.h"

#include "mac_mapper.h"

/**
 * @brief Supervisor structure definition
 * 
 */
struct supervisor_context {
  hmap_mac_conn   *mac_mapper;                                /**< MAC mapper connection structure */
  hmap_if_conn    *if_mapper;                                 /**< WiFi subnet to interface mapper */
  hmap_vlan_conn  *vlan_mapper;                               /**< WiFi VLAN to interface mapper */
  bool            allow_all_connections;                      /**< @c allow_all_connections Flag from @c struct app_config */
  bool            allow_all_nat;                              /**< @c allow_all_nat Flag from @c struct app_config */
  bool            exec_capture;                               /**< @c execute_capture from @c struct app_config */  
  char            hostapd_ctrl_if_path[MAX_OS_PATH_LEN];      /**< @c ctrl_interface param from @c struct hostapd_conf */
  uint8_t         wpa_passphrase[AP_SECRET_LEN];      /**< @c wpa_passphrase from @c struct hostapd_conf */
  ssize_t         wpa_passphrase_len;                         /**< the length of @c wpa_passphrase*/
  char            nat_interface[IFNAMSIZ];                    /**< @c nat_interface param from @c struct app_config */
  int             default_open_vlanid;                        /**< @c default_open_vlanid from @c struct app_config */
  char            db_path[MAX_OS_PATH_LEN];                   /**< @c db_path from @c struct app_config */
  UT_array        *config_ifinfo_array;                       /**< @c config_ifinfo_array from @c struct app_config */
  struct bridge_mac_list *bridge_list;                        /**< List of assigned bridges */
  char            domain_delim;                               /**< Cntrol server command delimiter */
  struct capture_conf capture_config;                         /**< Capture service configuration. */
  sqlite3         *fingeprint_db;                             /**< The fingerprint sqlite db structure. */
};

#endif