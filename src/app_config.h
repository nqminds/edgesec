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
 * @file app_config.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the app configuration structure.
 */
#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

#include <net/if.h>
#include <inttypes.h>
#include <stdbool.h>

#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/os.h"
#include "hostapd/hostapd_config.h"
#include "radius/radius_server.h"
#include "dns/dns_config.h"
#include "dhcp/dhcp_config.h"
#include "supervisor/supervisor_config.h"
/**
 * @brief The App configuration structures. Used for configuring the networking services.
 * 
 */
struct app_config {
  UT_array            *bin_path_array;                      /**< The array including the paths of systems binaries. */
  bool                ap_detect;                            /**< Flag to detect an existing wifi interface to create the access point. */
  bool                exec_hostapd;                         /**< Flag to execute the hostapd service. */
  bool                exec_radius;                          /**< Flag to execute the radius service. */
  bool                exec_dhcp;                            /**< Flag to execute the dhcp service. */
  char                nat_interface[IFNAMSIZ];              /**< The NAT interface string. */
  bool                create_interfaces;                    /**< Flag to create the WiFi subnet interfaces. */
  bool                ignore_if_error;                      /**< Flag if set ignores the errors if subnet already exists. */
  int                 default_open_vlanid;                  /**< Sets the default vlan index for open connections or if MAC is not in the list of connections. */
  UT_array            *config_ifinfo_array;                 /**< Interface list mapping bridge interface name and IP address range. */
  char                domain_server_path[MAX_OS_PATH_LEN];  /**< Path to the control server. */
  bool                allow_all_connections;                /**< Flag to allow all connections. */
  bool                kill_running_proc;                    /**< Flag to terminate running app processes. */
  UT_array            *connections;                         /**< MAC mapper to @c struct mac_conn. */
  struct radius_conf  rconfig;                              /**< Radius service configuration. */
  struct hostapd_conf hconfig;                              /**< Hostapd service configuration. */
  struct dns_conf     dns_config;                           /**< DNS service configuration. */
  struct dhcp_conf    dhcp_config;                          /**< DHCP service configuration. */
};

#endif