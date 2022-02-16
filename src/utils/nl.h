/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file nl.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the netlink utilities.
 */

#ifndef NL_H_
#define NL_H_

#include <linux/if.h>
#include <netinet/if_ether.h>
#include "linux/rtnetlink.h"

#include "utarray.h"

#ifdef DEBUG_LIBNL
#define NL_CB_TYPE NL_CB_DEBUG
#else
#define NL_CB_TYPE NL_CB_DEFAULT
#endif

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

/**
 * @brief Network wireless interface information structure
 * 
 */
typedef struct {
	char ifname[IFNAMSIZ];				/**< Interface string name */
	uint32_t ifindex;					/**< Interface index */
	uint64_t wdev;						/**< Physical interface wdev param */
	uint8_t addr[ETH_ALEN];				/**< Interface byte MAC address */
	uint32_t wiphy;						/**< Physical interface ID */
} netiw_info_t;

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char				buf[1024];
};

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 * 
 * @param if_id The intreface id, if 0 return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 */
UT_array *nl_get_interfaces(int if_id);


/**
 * @brief Create a interface object
 * 
 * @param if_name The interface string name
 * @param type The interface string type (ex. "bridge")
 * @return true on success, false otherwise
 */
bool nl_create_interface(char *if_name, char *type);

/**
 * @brief Set the interface IP
 * 
 * @param ip_addr The IP address string
 * @param brd_addr The broadcast IP address string
 * @param if_name The interface name string
 * @return true on success, false otherwise
 */
bool nl_set_interface_ip(char *ip_addr, char *brd_addr, char *if_name);

/**
 * @brief Set the interface state
 * 
 * @param if_name The interface name string
 * @param state The interface state value (true - "up", false - "down")
 * @return true on success, false otherwise
 */
bool nl_set_interface_state(char *if_name, bool state);

/**
 * @brief Check if wireless physical interface has VLAN capability
 * 
 * @param wiphy Wireless physical interface ID
 * @return true if capability present, false otherwise
 */
bool iwace_isvlan(uint32_t wiphy);

/**
 * @brief Get the array of all wireless physical interfaces
 * 
 * @return UT_array* The array of wireless physical interfaces
 */
UT_array *get_netiw_info(void);

/**
 * @brief Check if interface has the VLAN capability
 * 
 * @param ifname Interface name string
 * @return int 0 if VLAN capable, -1 on error and 1 if not VLAN capable
 */
int nl_is_iw_vlan(const char *ifname);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 * 
 * @param buf Interface working buffer
 * @return char* WiFi interface name
 */
char* nl_get_valid_iw(char *buf);

#endif