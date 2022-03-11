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

#include "dhcp_config.h"

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"


/**
 * @brief Generates the dnsmasq configuration file
 * 
 * @param dconf The dhcp configuration structure.
 * @param dns_server_array The array including the DNS servers IP addresses.
 * @return true on success, false otherwise
 */
int generate_dnsmasq_conf(struct dhcp_conf *dconf, UT_array *dns_server_array);

/**
 * @brief Generates the dnsmasq executable script for DHCP requests.
 * 
 * @param dhcp_script_path The dhcp executable script path string.
 * @param domain_server_path The UNIX domains server path.
 * @return 0 on success, -1 otherwise
 */
int generate_dnsmasq_script(char *dhcp_script_path, char *domain_server_path);

/**
 * @brief Execute the DHCP server
 * 
 * @param dhcp_bin_path The DHCP server binary path
 * @param dhcp_conf_path The DHCP server config path
 * @return char* The pointer to the statically allocated process name, NULL on failure
 */
char* run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path);

/**
 * @brief Terminate the DHCP server
 * 
 * @return bool true on success, false otherwise 
 */
bool kill_dhcp_process(void);

/**
 * @brief Signal the DHCP process to reload the config
 * 
 * @param dhcp_bin_path The DHCP server binary path
 * @param dhcp_conf_path The DHCP server config path
 * @return int 0 on success, -1 on failure
 */
int signal_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path);


/**
 * @brief Clear the DHCP lease entry for a MAC addrress
 * 
 * @param mac_addr The MAC address string
 * @param dhcp_leasefile_path The DHCP file path
 * @return int 0 on success, -1 on failure
 */
int clear_dhcp_lease_entry(char *mac_addr, char *dhcp_leasefile_path);
#endif