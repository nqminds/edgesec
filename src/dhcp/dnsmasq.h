/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of dnsmasq service configuration
 * utilities.
 */

#ifndef DNSMASQ_H
#define DNSMASQ_H

#include "dhcp_config.h"

#include "../utils/allocs.h"
#include "../utils/os.h"

/**
 * @brief Generates the dnsmasq configuration file
 *
 * @param dconf The dhcp configuration structure.
 * @param dns_server_array The array including the DNS servers IP addresses.
 * @return `0` on success, `-1` otherwise
 */
int generate_dnsmasq_conf(struct dhcp_conf *dconf, UT_array *dns_server_array);

/**
 * @brief Generates the dnsmasq executable script for DHCP requests.
 *
 * @param dhcp_script_path The dhcp executable script path string.
 * @param supervisor_control_path The UNIX domains supervisor control path.
 * @return 0 on success, -1 otherwise
 */
int generate_dnsmasq_script(char *dhcp_script_path,
                            char *supervisor_control_path);

/**
 * @brief Execute the DHCP server
 *
 * @param dhcp_bin_path The DHCP server binary path
 * @param dhcp_conf_path The DHCP server config path
 * @return char* The pointer to the statically allocated process name, NULL on
 * failure
 */
char *run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path);

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
 * @return int 0 on success, -1 on failure
 */
int signal_dhcp_process(char *dhcp_bin_path);

/**
 * @brief Clear the DHCP lease entry for a MAC addrress
 *
 * @param mac_addr The MAC address string
 * @param dhcp_leasefile_path The DHCP file path
 * @return int 0 on success, -1 on failure
 */
int clear_dhcp_lease_entry(char *mac_addr, char *dhcp_leasefile_path);

/**
 * @brief Creates the DHCP interface name for the given vlan id.
 *
 * @param dconf The dhcp configuration structure.
 * @param vlanid The vlan id.
 * @param[out] ifname The DHCP interface name.
 * @pre @p vlanid must be less than 4095 chars
 * @pre @p ifname must point to at least #IFNAMSIZ bytes.
 * @retval  0 Success
 * @retval -1 Error (invalid args)
 */
int define_dhcp_interface_name(const struct dhcp_conf *dconf, uint16_t vlanid,
                               char *ifname);
#endif
