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
 * @file dnsmasq.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of dnsmasq service configuration utilities.
 */

#ifndef DNSMASQ_H
#define DNSMASQ_H
#include <net/if.h>

#include "dhcp_config.h"
#include "../utils/os.h"
#include "../utils/utarray.h"


/**
 * @brief Generates the dnsmasq configuration file
 * 
 * @param dconf The dhcp configuration structure.
 * @param interface The WiFi AP interface name.
 * @param dns_server_array The array including the DNS servers IP addresses.
 * @return true on success, false otherwise
 */
bool generate_dnsmasq_conf(struct dhcp_conf *dconf, char *interface, UT_array *dns_server_array);

/**
 * @brief Generates the dnsmasq executable script for DHCP requests.
 * 
 * @param dhcp_script_path The dhcp executable script path string.
 * @param domain_server_path The UNIX domains server path.
 * @return true on success, false otherwise
 */
bool generate_dnsmasq_script(char *dhcp_script_path, char *domain_server_path);

/**
 * @brief Generates the DHCP configs
 * 
 * @param dconf The dhcp configuration structure.
 * @param interface The WiFi AP interface name.
 * @param dns_server_array The array including the DNS servers IP addresses.
 * @param domain_server_path The UNIX domains server path.
 * @return true on success, false otherwise
 */
bool generate_dhcp_configs(struct dhcp_conf *dconf, char *interface, UT_array *dns_server_array, char *domain_server_path);

/**
 * @brief Execute the DHCP server
 * 
 * @param dhcp_bin_path The DHCP server binary path
 * @param dhcp_conf_path The DHCP server config path
 * @return int 0 on success, -1 on error
 */
int run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path);
#endif