/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the network utilities.
 */

#ifndef NET_H_
#define NET_H_

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include <utarray.h>
#include <uthash.h>
#include "allocs.h"
#include "os.h"

#define IP_ALEN 4
#define OS_INET_ADDRSTRLEN 22
#define OS_INET6_ADDRSTRLEN 63

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACSTR_LEN 18 // Including the '\0' character
/*
 * Compact form for string representation of MAC address
 * To be used, e.g., for constructing dbus paths for P2P Devices
 */
#define COMPACT_MACSTR "%02x%02x%02x%02x%02x%02x"
#define COMPACT_MACSTR_LEN 13 // Including the '\0' character
#endif

#ifndef IP2STR
#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPSTR "%d.%d.%d.%d"
#endif

#ifndef IP62STR
#define IP62STR(a)                                                             \
  (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5], (a)[6], (a)[7], (a)[8],      \
      (a)[9], (a)[10], (a)[11], (a)[12], (a)[13], (a)[14], (a)[15]
#define IP6STR                                                                 \
  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#endif

/**
 * @brief Checks whether a string denotes a IPv4 address
 *
 * @param ip The IP in fromat x.y.z.q
 * @return true if the string is an IP, false otherwise
 */
bool validate_ipv4_string(char *ip);

/**
 * @brief IP string to @c struct in_addr_t converter
 *
 * @param ip The IP address string
 * @param subnetMask The IP address subnet mask
 * @param addr The output @c struct in_addr_t value
 * @return 0 on success, -1 on failure
 */
int ip_2_nbo(char *ip, char *subnetMask, in_addr_t *addr);

/**
 * @brief IP string to buffer
 *
 * @param ip The IP address string
 * @param buf The output buffer of size IP_ALEN
 * @return 0 on success, -1 on failure
 */
int ip4_2_buf(char *ip, uint8_t *buf);

/**
 * @brief Convert a 32 bit number IP to an IP string
 *
 * @param addr The IP in 32 bit format
 * @param ip The input buffer to store the IP
 * @return char* Pointer to the returned IP
 */
const char *bit32_2_ip(uint32_t addr, char *ip);

/**
 * @brief Convert the in_addr encoded IP4 address to an IP string
 *
 * @param addr The in_addr encoded IP
 * @param ip The input buffer to store the IP
 * @return char* Pointer to the returned IP
 */
const char *inaddr4_2_ip(struct in_addr *addr, char *ip);

/**
 * @brief Convert the in6_addr encoded IP6 address to an IP string
 *
 * @param addr The in6_addr encoded IP
 * @param ip The input buffer to store the IP
 * @return char* Pointer to the returned IP
 */
const char *inaddr6_2_ip(struct in6_addr *addr, char *ip);

/**
 * @brief Convert from a string subnet mask to a short integer version
 *
 * @param subnet_mask The subnet mask string
 * @return The short integer version subnet mask
 */
uint8_t get_short_subnet(const char *subnet_mask);

/**
 * @brief Get the host identifier from an IP address string
 *
 * @param ip The IP address string
 * @param subnet_mask The subnet mask string
 * @param host The returned host indentifier
 * @return 0 on success, -1 on failure
 */
int get_ip_host(char *ip, char *subnet_mask, uint32_t *host);

/**
 * @brief Disable the PMTU discovery for sockets
 *
 * @param[in] sock The socket descriptor
 * @return 0 on success, -1 on failure
 */
int disable_pmtu_discovery(int sock);

/**
 * @brief Convert ASCII string to MAC address (in any known format)
 *
 * @authors Jouni Malinen <j@w1.fi> and wpa_supplicant contributors
 * @date 2003-2019
 * @copyright BSD
 * @see
 * https://w1.fi/wpa_supplicant/devel/common_8h.html#ab7ec8839c8e817e241c52ad7a0299be3
 *
 * @param[in] txt MAC address as a string (e.g., 00:11:22:33:44:55 or
 * 0011.2233.4455)
 * @param[out] addr Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * @return int Characters used (> 0) on success, -1 on failure
 */
int hwaddr_aton2(const char *txt, uint8_t *addr);

#endif
