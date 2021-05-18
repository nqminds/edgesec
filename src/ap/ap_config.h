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
 * @file ap_config.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of AP config structures.
 */

#ifndef CONFIG_GENERATOR_H
#define CONFIG_GENERATOR_H

#include <sys/types.h>
#include <net/if.h>
#include <stdbool.h>

#include "../utils/os.h"
#include "../radius/radius_server.h"

#define AP_NAME_LEN           32
#define AP_SECRET_LEN         64
#define AP_DRIVE_LEN          20
#define AP_HWMODE_LEN         4
#define AP_WPA_KEY_MGMT_LEN   20
#define AP_RSN_PAIRWISE_LEN   20

/**
 * @brief The hostapd configuration structure
 * 
 */
struct apconf {
  char ap_bin_path[MAX_OS_PATH_LEN];             /**< The AP binary path string */
  char ap_file_path[MAX_OS_PATH_LEN];            /**< The AP file configuration path string */
  char ap_log_path[MAX_OS_PATH_LEN];             /**< The AP log path string */
  char interface[IFNAMSIZ];                           /**< The hostapd @c interface param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char ssid[AP_NAME_LEN];                     /**< The hostapd @c ssid param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char wpa_passphrase[AP_SECRET_LEN];         /**< WiFi AP password if @c struct app_config::allow_all_connections flag is set */
  char bridge[IFNAMSIZ];                              /**< The hostapd @c bridge param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char driver[AP_DRIVE_LEN];                     /**< The hostapd @c driver param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char hw_mode[AP_HWMODE_LEN];                   /**< The hostapd @c hw_mode param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int channel;                                        /**< The hostapd @c channel param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int wmm_enabled;                                    /**< The hostapd @c wmm_enabled param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int auth_algs;                                      /**< The hostapd @c auth_algs param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int wpa;                                            /**< The hostapd @c wpa param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char wpa_key_mgmt[AP_WPA_KEY_MGMT_LEN];        /**< The hostapd @c wpa_key_mgmt param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char rsn_pairwise[AP_RSN_PAIRWISE_LEN];        /**< The hostapd @c rsn_pairwise param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char ctrl_interface[MAX_OS_PATH_LEN];               /**< The hostapd @c ctrl_interface param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int macaddr_acl;                                    /**< The hostapd @c macaddr_acl param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int dynamic_vlan;                                   /**< The hostapd @c dynamic_vlan param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char vlan_bridge[IFNAMSIZ];                         /**< The hostapd @c vlan_bridge param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char vlan_file[MAX_OS_PATH_LEN];                    /**< The hostapd @c vlan_file param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int logger_stdout;                                  /**< The hostapd @c logger_stdout param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int logger_stdout_level;                            /**< The hostapd @c logger_stdout_level param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int logger_syslog;                                  /**< The hostapd @c logger_syslog param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int logger_syslog_level;                            /**< The hostapd @c logger_syslog_level param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int ignore_broadcast_ssid;                          /**< The hostapd @c ignore_broadcast_ssid param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int wpa_psk_radius;                                 /**< The hostapd @c wpa_psk_radius param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char vlan_tagged_interface[MAX_OS_PATH_LEN];        /**< The hostapd @c vlan_tagged_interface param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
};

#endif