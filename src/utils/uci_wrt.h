/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the uci utilities.
 */

#ifndef UCI_H_
#define UCI_H_

#include <uci.h>
#include <utarray.h>

#include "os.h"
#include "squeue.h"

struct uctx {
  struct uci_context *uctx;
  char path[MAX_OS_PATH_LEN];
};

struct hostapd_params {
  char *device;
  int auth_algs;
  int wpa;
  char *wpa_key_mgmt;
  char *rsn_pairwise;
  char *radius_client_ip;
  char *radius_server_ip;
  int radius_port;
  char *radius_secret;
  int macaddr_acl;
  int dynamic_vlan;
  char *vlan_file;
  int ignore_broadcast_ssid;
  int wpa_psk_radius;
  char *vlan_bridge;
  char *ssid;
  char *wpa_passphrase;
};

/**
 * @brief Initialises the uci context
 *
 * @param path The path string to the config folder
 * @return The uci context, or `NULL` on error.
 * This return variable must be cleaned up by uwrt_free_context().
 */
struct uctx *uwrt_init_context(const char *path);

/**
 * @brief Frees the uci context
 *
 * @param context The uci context
 */
void uwrt_free_context(struct uctx *context);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 *
 * @param context The uci context
 * @param ifname The interface name, if NULL return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 * This return variable must be cleaned up by utarray_free().
 */
UT_array *uwrt_get_interfaces(const struct uctx *context, const char *ifname);

/**
 * @brief Assigns an IP to an interface
 *
 * @param context The uci context
 * @param ifname The interface name
 * @param ip_addr The interface IP4 address
 * @param netmask The interface IP4 netmask
 * @return int 0 on success, -1 on failure
 */
int uwrt_set_interface_ip(const struct uctx *context, const char *ifname,
                          const char *ip_addr, const char *netmask);
/**
 * @brief Creates and interface and assigns an IP
 *
 * @param context The uci context
 * @param ifname The interface name
 * @param type The interface type
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param netmask The interface IP4 netmask
 * @return int 0 on success, -1 on failure
 */
int uwrt_create_interface(const struct uctx *context, const char *ifname,
                          const char *type, const char *ip_addr,
                          const char *brd_addr, const char *netmask);

/**
 * @brief Commit a uci section
 *
 * @param context The uci context
 * @param section The uci section
 * @return int 0 on success, -1 on failure
 */
int uwrt_commit_section(const struct uctx *context, const char *section);

/**
 * @brief Generates a dnsmasq uci instance
 *
 * @param context The uci context
 * @param ifname_queue The interface queue
 * @param server_array The array of servers
 * @param leasefile The lease file path string
 * @param scriptfile The script file path string
 * @return int 0 on success, -1 on failure
 */
int uwrt_gen_dnsmasq_instance(const struct uctx *context,
                              const struct string_queue *ifname_queue,
                              const UT_array *server_array,
                              const char *leasefile, const char *scriptfile);

/**
 * @brief Adds a dhcp pool entry
 *
 * @param context The uci context
 * @param ifname The interface name
 * @param ip_addr_low Interface string IP address lower bound
 * @param ip_addr_upp Interface string IP address upper bound
 * @param subnet_mask Interface string IP subnet mask
 * @param lease_time Interface lease time string
 * @return int 0 on success, -1 on failure
 */
int uwrt_add_dhcp_pool(const struct uctx *context, const char *ifname,
                       const char *ip_addr_low, const char *ip_addr_upp,
                       const char *subnet_mask, const char *lease_time);

/**
 * @brief Generate the hostapd config
 *
 * @param context The uci context
 * @param params The hostapd params
 * @return int 0 on success, -1 on failure
 */
int uwrt_gen_hostapd_instance(const struct uctx *context,
                              const struct hostapd_params *params);

/**
 * @brief Generate a firewall zone for a bridge
 *
 * @param context The uci context
 * @param brname The bridge name
 * @return int 0 on success, -1 on failure
 */
int uwrt_gen_firewall_zone(const struct uctx *context, const char *brname);

/**
 * @brief Adds a firewall rule for an IP address
 *
 * @param context The uci context
 * @param brname The bridge name
 * @param ip_addr The IP address
 * @param nat_name The NAT bridge name
 * @return int 0 on success, -1 on failure
 */
int uwrt_add_firewall_nat(const struct uctx *context, const char *brname,
                          const char *ip_addr, const char *nat_name);

/**
 * @brief Deletes a firewall rule for an IP address
 *
 * @param context The uci context
 * @param ip_addr The IP address
 * @return int 0 on success, -1 on failure
 */
int uwrt_delete_firewall_nat(const struct uctx *context, const char *ip_addr);

/**
 * @brief Adds a firewall bridge rule for two IP addresses
 *
 * @param context The uci context
 * @param sip The source IP address
 * @param sbr The source bridge interface name
 * @param dip The destination IP address
 * @param dbr The destination bridge interface name
 * @return int 0 on success, -1 on failure
 */
int uwrt_add_firewall_bridge(const struct uctx *context, const char *sip,
                             const char *sbr, const char *dip, const char *dbr);

/**
 * @brief Deletes a firewall bridge rule for two IP addresses
 *
 * @param context The uci context
 * @param sip The source IP address
 * @param dip The destination IP address
 * @return int 0 on success, -1 on failure
 */
int uwrt_delete_firewall_bridge(const struct uctx *context, const char *sip,
                                const char *dip);

/**
 * @brief Removes all the firewall rules
 *
 * @param context The uci context
 * @return int 0 on success, -1 on failure
 */
int uwrt_cleanup_firewall(const struct uctx *context);
#endif
