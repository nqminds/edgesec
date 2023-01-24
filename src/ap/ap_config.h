/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of AP config structures.
 *
 * Defines the access point (AP) configuration structure used to configure the
 * AP service.
 */

#ifndef CONFIG_GENERATOR_H
#define CONFIG_GENERATOR_H

#include <stdbool.h>
#include <net/if.h>
#include <sys/types.h>

#include "../utils/os.h"

#define AP_NAME_LEN 32 /* Maximum length of the AP name, i.e., ESSID name */
#define AP_SECRET_LEN                                                          \
  64 /* Maximum length of the AP secret, i.e., ESSID secret */
#define AP_DRIVE_LEN 20 /* Maximum length of the AP driver name */
#define AP_HWMODE_LEN                                                          \
  4 /* Maximum size of the hostapd @c hw_mode param @see                       \
       https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
#define AP_WPA_KEY_MGMT_LEN                                                    \
  20 /* Maximum size of the hostapd @c wpa_key_mgmt param @see                 \
        https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
#define AP_RSN_PAIRWISE_LEN                                                    \
  20 /* Maximum size of the hostapd @c rsn_pairwise param @see                 \
        https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */

/**
 * @brief The AP conection status
 *
 * Defines the connection state for a station connected to the AP.
 */
enum AP_CONNECTION_STATUS {
  AP_DEFAULT_STATUS = 0,
  AP_CONNECTED_STATUS,
  AP_DISCONNECTED_STATUS
};

/**
 * @brief The hostapd configuration structure
 *
 */
struct apconf {
  char ap_bin_path[MAX_OS_PATH_LEN];  /**< The AP binary path string */
  char ap_file_path[MAX_OS_PATH_LEN]; /**< The AP file configuration path string
                                       */
  char ap_log_path[MAX_OS_PATH_LEN];  /**< The AP log path string */
  char ctrl_interface_path[MAX_OS_PATH_LEN]; /**< The path constructed as
                                                ctrl_interface/interface  */
  char
      interface[IF_NAMESIZE]; /**< The hostapd @c interface param @see
                              https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                            */
  char device[IF_NAMESIZE];   /**< The hostapd uci device id*/
  char
      ssid[AP_NAME_LEN];              /**< The hostapd @c ssid param @see
                                         https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                                       */
  char wpa_passphrase[AP_SECRET_LEN]; /**< WiFi AP password if @c struct
                                         app_config::allow_all_connections flag
                                         is set */
  char driver
      [AP_DRIVE_LEN]; /**< The hostapd @c driver param @see
                         https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                       */
  char hw_mode
      [AP_HWMODE_LEN]; /**< The hostapd @c hw_mode param @see
                          https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                        */
  int channel;         /**< The hostapd @c channel param @see
                          https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int wmm_enabled;     /**< The hostapd @c wmm_enabled param @see
                          https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int auth_algs;       /**< The hostapd @c auth_algs param @see
                          https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int wpa;             /**< The hostapd @c wpa param @see
                          https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char wpa_key_mgmt
      [AP_WPA_KEY_MGMT_LEN]; /**< The hostapd @c wpa_key_mgmt param
                                @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                              */
  int ieee8021x;             /**< The hostapd @c ieee8021x param @see
                               https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char rsn_pairwise
      [AP_RSN_PAIRWISE_LEN]; /**< The hostapd @c rsn_pairwise param
                                @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                              */
  char ctrl_interface
      [MAX_OS_PATH_LEN]; /**< The hostapd @c ctrl_interface param
                            @see
                            https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                          */
  int macaddr_acl;       /**< The hostapd @c macaddr_acl param @see
                            https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int dynamic_vlan;      /**< The hostapd @c dynamic_vlan param @see
                            https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char vlan_bridge
      [IF_NAMESIZE]; /**< The hostapd @c vlan_bridge param @see
                     https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                   */
  char vlan_file
      [MAX_OS_PATH_LEN];     /**< The hostapd @c vlan_file param @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                              */
  int logger_stdout;         /**< The hostapd @c logger_stdout param @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int logger_stdout_level;   /**< The hostapd @c logger_stdout_level param @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                              */
  int logger_syslog;         /**< The hostapd @c logger_syslog param @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  int logger_syslog_level;   /**< The hostapd @c logger_syslog_level param @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                              */
  int ignore_broadcast_ssid; /**< The hostapd @c ignore_broadcast_ssid param
                                @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
                              */
  int wpa_psk_radius;        /**< The hostapd @c wpa_psk_radius param @see
                                https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
  char vlan_tagged_interface
      [IF_NAMESIZE]; /**< The hostapd @c vlan_tagged_interface param @see
                     https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf */
};

#endif
