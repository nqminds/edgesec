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
 * @file config_generator.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of hostapd config generation utilities.
 */

#ifndef CONFIG_GENERATOR_H
#define CONFIG_GENERATOR_H

#include <sys/types.h>
#include <net/if.h>
#include <stdbool.h>

#include "../utils/os.h"
#include "../radius/radius_server.h"

#define HOSTAPD_AP_NAME_LEN       32
#define HOSTAPD_AP_SECRET_LEN     64
#define HOSTAPD_DRIVE_LEN         20
#define HOSTAPD_HWMODE_LEN        4
#define HOSTAPD_WPA_KEY_MGMT_LEN  20
#define HOSTAPD_RSN_PAIRWISE_LEN  20

/**
 * @brief The hostapd configuration structure
 * 
 */
struct hostapd_conf {
  char hostapd_bin_path[MAX_OS_PATH_LEN];             /**< The hostapd binary path string */
  char hostapd_file_path[MAX_OS_PATH_LEN];            /**< The hostapd file configuration path string */
  char hostapd_log_path[MAX_OS_PATH_LEN];             /**< The hostapd log path string */
  char interface[IFNAMSIZ];                           /**< The hostapd @c interface param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char ssid[HOSTAPD_AP_NAME_LEN];                     /**< The hostapd @c ssid param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char wpa_passphrase[HOSTAPD_AP_SECRET_LEN];         /**< WiFi AP password if @c struct app_config::allow_all_connections flag is set */
  char bridge[IFNAMSIZ];                              /**< The hostapd @c bridge param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char driver[HOSTAPD_DRIVE_LEN];                     /**< The hostapd @c driver param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char hw_mode[HOSTAPD_HWMODE_LEN];                   /**< The hostapd @c hw_mode param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int channel;                                        /**< The hostapd @c channel param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int wmm_enabled;                                    /**< The hostapd @c wmm_enabled param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int auth_algs;                                      /**< The hostapd @c auth_algs param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int wpa;                                            /**< The hostapd @c wpa param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char wpa_key_mgmt[HOSTAPD_WPA_KEY_MGMT_LEN];        /**< The hostapd @c wpa_key_mgmt param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char rsn_pairwise[HOSTAPD_RSN_PAIRWISE_LEN];        /**< The hostapd @c rsn_pairwise param @see https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
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
};

/**
 * @brief Generates and saves the hostapd configuration files
 * 
 * @param hconf The hostapd configuration structure
 * @param rconf The radius configuration structure
 * @return true if config file saved, false otherwise
 */
bool generate_hostapd_conf(struct hostapd_conf *hconf, struct radius_conf *rconf);

/**
 * @brief Generates and save the VLAN configuration file
 * 
 * @param vlan_file The VLAN configuration file path
 * @param interface The WiFi AP interface name
 * @return true  if VLAN config file saved, false otherwise
 */
bool generate_vlan_conf(char *vlan_file, char *interface);

/**
 * @brief Construct the hostapd control interface path
 * 
 * @param ctrl_interface The control interface path
 * @param interface The WiFi interface name
 * @param hostapd_ctrl_if_path Returned hostapd control interface path (buffer has to be preallocated)
 * @return true on success, false otherwise
 */
bool construct_hostapd_ctrlif(char *ctrl_interface, char *interface, char *hostapd_ctrl_if_path);
#endif