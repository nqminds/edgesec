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
#include "../dhcp/dhcp_config.h"
#include "../dns/dns_config.h"
#include "../utils/iface.h"
#include "../capture/capture_config.h"
#include "../crypt/crypt_config.h"

#include "mac_mapper.h"

/**
 * @brief Authentication ticket structure definition
 * 
 */
struct auth_ticket {
  uint8_t         passphrase[AP_SECRET_LEN];              /**< the ticket passphrase */
  ssize_t         passphrase_len;                         /**< the ticket passphrase length */
  char            device_label[MAX_DEVICE_LABEL_SIZE];    /**< the device label */
  int             vlanid;                                 /**< the ticket associated VLAN ID */
  uint8_t         issuer_mac_addr[ETH_ALEN];              /**< Issuer MAC */
};

/**
 * @brief Supervisor structure definition
 * 
 */
struct supervisor_context {
  hmap_mac_conn   *mac_mapper;                                /**< MAC mapper connection structure */
  hmap_if_conn    *if_mapper;                                 /**< WiFi subnet to interface mapper */
  hmap_vlan_conn  *vlan_mapper;                               /**< WiFi VLAN to interface mapper */
  hmap_str_keychar *hmap_bin_paths;                           /**< Mapper for paths to systems binaries */
  bool            allow_all_connections;                      /**< @c allow_all_connections Flag from @c struct app_config */
  bool            allow_all_nat;                              /**< @c allow_all_nat Flag from @c struct app_config */
  bool            exec_capture;                               /**< @c execute_capture from @c struct app_config */  
  uint8_t         wpa_passphrase[AP_SECRET_LEN];              /**< @c wpa_passphrase from @c struct hostapd_conf */
  ssize_t         wpa_passphrase_len;                         /**< the length of @c wpa_passphrase*/
  char            nat_interface[IFNAMSIZ];                    /**< @c nat_interface param from @c struct app_config */
  bool            allocate_vlans;                             /**< @c allocate_vlans from @c struct app_config */
  int             default_open_vlanid;                        /**< @c default_open_vlanid from @c struct app_config */
  int             quarantine_vlanid;                          /**< @c quarantine_vlanid from @c struct app_config */
  int             risk_score;                                 /**< @c risk_score from @c struct app_config */
  char            db_path[MAX_OS_PATH_LEN];                   /**< @c db_path from @c struct app_config */
  UT_array        *config_ifinfo_array;                       /**< @c config_ifinfo_array from @c struct app_config */
  UT_array        *subscribers_array;                         /**< The array of events subscribers */
  struct bridge_mac_list *bridge_list;                        /**< List of assigned bridges */
  char            domain_delim;                               /**< Control server command delimiter */
  int             domain_sock;                                /**< The domain socket */
  char            nat_ip[OS_INET_ADDRSTRLEN];                 /**< The NAT IP address */
  struct capture_conf capture_config;                         /**< Capture service configuration. */
  struct apconf       hconfig;                                /**< AP service configuration. */
  struct radius_conf  rconfig;                                /**< Radius service configuration. */
  struct dhcp_conf  dconfig;                                  /**< DHCP service configuration. */
  struct dns_conf  nconfig;                                   /**< DNS service configuration. */
  struct mdns_conf  mconfig;                                   /**< DNS service configuration. */
  sqlite3         *fingeprint_db;                             /**< The fingerprint sqlite db structure. */
  sqlite3         *alert_db;                                  /**< The alert sqlite db structure. */
  sqlite3         *macconn_db;                                /**< The macconn db structure. */
  struct radius_server_data *radius_srv;                      /**< The radius server context. */
  struct iptables_context *iptables_ctx;                      /**< The iptables context. */
  struct crypt_context *crypt_ctx;                            /**< The crypt context. */
  struct auth_ticket *ticket;                                 /**< The authentication ticket. */  
  int              ap_sock;                                   /**< The AP notifier socket. */
};

#endif