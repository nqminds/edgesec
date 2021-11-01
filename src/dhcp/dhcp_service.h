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
 * @file dhcp_service.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of dhcp service configuration utilities.
 */
#ifndef DHCP_SERVICE_H
#define DHCP_SERVICE_H

#include "dhcp_config.h"

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

/**
 * @brief Run the DHCP server
 * 
 * @param dhcp_bin_path The dhcp server binary path
 * @param dconf The dhcp configuration structures.
 * @param interface The WiFi AP interface name.
 * @param dns_server_array The array including the DNS servers IP addresses.
 * @param domain_server_path The UNIX domain server path.
 * @param exec_dhcp Flag to execute/signal the DHCP process.
 * @return int 0 on success, -1 on error
 */
int run_dhcp(char *dhcp_bin_path, struct dhcp_conf *dconf,
  char *interface, UT_array *dns_server_array, char *domain_server_path,
  bool exec_dhcp);

/**
 * @brief Closes (terminates) dhcp process
 * 
 * @return true success, false otherwise
 */
bool close_dhcp(void);

/**
 * @brief Clear the DHCP lease for a MAC addrress
 * 
 * @param mac_addr The MAC address string
 * @param dconf The dhcp configuration structures
 * @return int 0 on success, -1 on failure
 */
int clear_dhcp_lease(char *mac_addr, struct dhcp_conf *dconf);
#endif