/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file config.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the app configuration utilities.
 */
#ifndef CONFIG_H
#define CONFIG_H

#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "ap/ap_config.h"
#include "radius/radius_server.h"
#include "dns/dns_config.h"
#include "dhcp/dhcp_config.h"
#include "supervisor/supervisor_config.h"
#include "capture/capture_config.h"

#define MAX_USER_SECRET 255
#define MAX_SALT_STRING_SIZE 255

/**
 * @brief The App configuration structures. Used for configuring the networking
 * services.
 *
 */
struct app_config {
  UT_array *
      bin_path_array; /**< The array including the paths of systems binaries. */
  bool ap_detect; /**< Flag to detect an existing wifi interface to create the
                     access point. */
  bool exec_ap;   /**< Flag to execute the ap service. */
  bool generate_ssid;     /**< Flag to generate the SSID for AP. */
  bool exec_radius;       /**< Flag to execute the radius service. */
  bool exec_dhcp;         /**< Flag to execute the dhcp service. */
  bool exec_capture;      /**< Flag to execute the capture service. */
  bool exec_mdns_forward; /**< Flag to execute the mdns forwarding service. */
  bool exec_firewall;     /**< Flag to execute the firewall command. */
  char nat_bridge[IFNAMSIZ];       /**< The NAT bridge string. */
  char nat_interface[IFNAMSIZ];    /**< The NAT interface string. */
  char bridge_prefix[IFNAMSIZ];    /**< The bridge prefix. */
  char interface_prefix[IFNAMSIZ]; /**< The interface prefix. */
  bool create_interfaces; /**< Flag to create the WiFi subnet interfaces. */
  bool ignore_if_error;   /**< Flag if set ignores the errors if subnet already
                             exists. */
  bool allocate_vlans; /**< Flag if set allocates a random vlan for a device. */
  int default_open_vlanid; /**< Sets the default vlan index for open connections
                              or if MAC is not in the list of connections. */
  int quarantine_vlanid; /**< Sets the vlan index for the quarantine MACs, -1 if
                            there's no quarantine vlan. */
  UT_array *config_ifinfo_array; /**< Interface list mapping bridge interface
                                    name and IP address range. */
  unsigned int supervisor_control_port; /**< The port number for the supervisor
                                           control server */
  char supervisor_control_path[MAX_OS_PATH_LEN]; /**< Path to the control
                                                    server. */
  char connection_db_path[MAX_OS_PATH_LEN];      /**< Specifies the path to the
                                                    connection sqlite3 dbs */
#ifdef WITH_CRYPTO_SERVICE
  char crypt_db_path[MAX_OS_PATH_LEN]; /**< Specifies the crypt db path to the
                                          sqlite3 db */
  char crypt_key_id[MAX_KEY_ID_SIZE];  /**< Specifies the crypt key id */
  char crypt_secret[MAX_USER_SECRET];  /**< Specifies the crypt user master
                                          secret */
#endif
  bool allow_all_connections; /**< Flag to allow all connections. */
  bool allow_all_nat;         /**< Flag to allow all nat connections. */
  bool kill_running_proc;     /**< Flag to terminate running app processes. */
  bool set_ip_forward; /**< Flag to set the ip forward os system param. */
  char pid_file_path[MAX_OS_PATH_LEN];   /**< Path to the pid file. */
  char config_ini_path[MAX_OS_PATH_LEN]; /**< Path to the config.ini file. */
  struct radius_conf rconfig;            /**< Radius service configuration. */
  struct apconf hconfig;                 /**< AP service configuration. */
  struct dns_conf dns_config;            /**< DNS service configuration. */
  struct mdns_conf mdns_config;          /**< mDNS service configuration. */
  struct dhcp_conf dhcp_config;          /**< DHCP service configuration. */
  struct capture_conf capture_config;    /**< Capture service configuration. */
  struct firewall_conf firewall_config;  /**< Firewall service configuration. */
};

/**
 * @brief Load the app configuration
 *
 * @param filename The app configuration file
 * @param config The configuration structure
 * @return true on success, false otherwise
 */
bool load_app_config(const char *filename, struct app_config *config);

/**
 * @brief Frees the app configuration
 *
 * @param config The app configuration structure
 * @return true on success, false otherwise
 */
void free_app_config(struct app_config *config);

/**
 * @brief Loads the capture config
 *
 * @param filename The app configuration file
 * @param config The capture configuration structure
 * @return true on success, false otherwise
 */
bool load_capture_config(const char *filename, struct capture_conf *config);

/**
 * @brief Loads the system config
 *
 * @param filename The app configuration file
 * @param config The app configuration structure
 * @return true on success, false otherwise
 */
bool load_system_config(const char *filename, struct app_config *config);

/**
 * @brief Loads the supervisor config
 *
 * @param filename The app configuration file
 * @param config The app configuration structure
 * @return true on success, false otherwise
 */
bool load_supervisor_config(const char *filename, struct app_config *config);

/**
 * @brief Loads the mDNS config
 *
 * @param filename The app configuration file
 * @param config The app configuration structure
 * @return true on success, false otherwise
 */
bool load_mdns_conf(const char *filename, struct app_config *config);

/**
 * @brief Loads the list of interfaces
 *
 * @param filename The app configuration file
 * @param config The app configuration structure
 * @return true on success, false otherwise
 */
bool load_interface_list(const char *filename, struct app_config *config);

/**
 * @brief Loads the AP config
 *
 * @param filename The app configuration file
 * @param config The app configuration structure
 * @return true on success, false otherwise
 */
bool load_ap_conf(const char *filename, struct app_config *config);
#endif
