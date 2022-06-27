/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file dhcp_service.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of dhcp service configuration
 * utilities.
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
 * @param dconf The dhcp configuration structures.
 * @param dns_server_array The array including the DNS servers IP addresses.
 * @param supervisor_control_path The UNIX domain control path.
 * @param exec_dhcp Flag to execute/signal the DHCP process.
 * @return int 0 on success, -1 on error
 */
int run_dhcp(struct dhcp_conf *dconf, UT_array *dns_server_array,
             char *supervisor_control_path, bool exec_dhcp);

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
