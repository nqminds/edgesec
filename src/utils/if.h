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
 * @file if.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the network interface utilities.
 */

#ifndef IF_H_
#define IF_H_

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "linux/rtnetlink.h"
#include "utarray.h"
#include "uthash.h"
#include "os.h"

enum IF_STATE{
	IF_STATE_UNKNOWN = 0,
	IF_STATE_NOTPRESENT,
	IF_STATE_DOWN,
	IF_STATE_LOWERLAYERDOWN,
	IF_STATE_TESTING,
	IF_STATE_DORMANT,
	IF_STATE_UP,
	IF_STATE_OTHER,
};

/**
 * @brief Network interface definition structure
 * 
 */
typedef struct {
	char 			ifname[IFNAMSIZ];					/**< Interface string name */
	uint32_t 		ifindex;							/**< Interface index value */
	enum IF_STATE 	state;								/**< Interface state */
	char 			link_type[LINK_TYPE_LEN];			/**< Interface link type */
	uint8_t 		ifa_family;							/**< Interface family */
	char 			ip_addr[IP_LEN];					/**< Interface string IP address */
	char 			peer_addr[IP_LEN];					/**< Interface string peer IP address */
	char 			brd_addr[IP_LEN];					/**< Interface string IP broadcast address */
	uint8_t 		mac_addr[ETH_ALEN];					/**< Interface byte MAC address */
} netif_info_t;

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char				buf[1024];
};

/**
 * @brief Interface configuration info structure
 * 
 */
typedef struct config_ifinfo_t{
  int       				vlanid;                 /**< Interface VLAN ID */
  char 						ifname[IFNAMSIZ];		/**< Interface string name */
  char 						ip_addr[IP_LEN];		/**< Interface string IP address */
  char 						brd_addr[IP_LEN];		/**< Interface string IP broadcast address */
  char 						subnet_mask[IP_LEN];	/**< Interface string IP subnet mask */
} config_ifinfo_t;

/**
 * @brief Interface connection mapper
 * 
 */
typedef struct hashmap_if_conn {
    in_addr_t 					key;               		/**< key as subnet */
    char 						value[IFNAMSIZ];		/**< value as the interface name */
    UT_hash_handle 				hh;         		    /**< makes this structure hashable */
} hmap_if_conn;

/**
 * @brief IP string to @c struct in_addr_t converter
 * 
 * @param ip The IP address string
 * @param subnetMask The IP address subnet mask
 * @param addr The output @c struct in_addr_t value
 * @return true on success, false otherwise
 */
bool ip_2_nbo(char *ip, char *subnetMask, in_addr_t *addr);

/**
 * @brief Get the interface name corresponding to an IP address of the subnet
 * 
 * @param hmap The interface connection mapper object
 * @param subnet The IP address of the subnet
 * @param ifname The returned interface name 
 * @return int 1 if found, 0 not found, -1 on error
 */
int get_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname);

/**
 * @brief Insertes an interface and subnet IP value into the interface connection mapper
 * 
 * @param hmap The interface connection mapper object
 * @param subnet The IP address of the subnet
 * @param ifname The interface name
 * @return true on success, false otherwise
 */
bool put_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname);

/**
 * @brief Frees the interface connection mapper object
 * 
 * @param hmap The interface connection mapper object
 */
void free_if_mapper(hmap_if_conn **hmap);

/**
 * @brief Check if an interface exist (network system check)
 * 
 * @param ifname The interface string namre
 * @return true if it exist, false otherwise
 */
bool iface_exists(const char *ifname);

/**
 * @brief Create a interface object
 * 
 * @param if_name The interface string name
 * @param type The interface string type (ex. "bridge")
 * @return true on success, false otherwise
 */
bool create_interface(char *if_name, char *type);

/**
 * @brief Set the interface IP
 * 
 * @param ip_addr The IP address string
 * @param brd_addr The broadcast IP address string
 * @param if_name The interface name string
 * @return true on success, false otherwise
 */
bool set_interface_ip(char *ip_addr, char *brd_addr, char *if_name);

/**
 * @brief Set the interface state
 * 
 * @param if_name The interface name string
 * @param state The interface state value (true - "up", false - "down")
 * @return true on success, false otherwise
 */
bool set_interface_state(char *if_name, bool state);

/**
 * @brief Resets the interface
 * 
 * @param if_name The interface name string
 * @return true on success, false otherwise
 */
bool reset_interface(char *if_name);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 * 
 * @param if_id The intreface id, if 0 return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 */
UT_array *get_interfaces(int if_id);

/**
 * @brief Returns the subnet address as a in_addr_t type from an IP address and an array of interface configuration info structure.
 * 
 * @param config_ifinfo_array The array of interface configuration structures.
 * @param ip The IP Address
 * @param subnet_addr The returned subnet address
 * @return 0 on success, -1 on error and 1 if IP is not in any subnets
 */
int find_subnet_address(UT_array *config_ifinfo_array, char *ip, in_addr_t *subnet_addr);

/**
 * @brief Get the interface name from an IP string
 * 
 * @param if_mapper The mapper from VLAn to interface
 * @param config_ifinfo_array The list of IP subnets
 * @param ip The input IP address
 * @param ifname The returned interface name (string has to be preallocated)
 * @return true on success, false otherwise
 */
bool get_ifname_from_ip(hmap_if_conn **if_mapper, UT_array *config_ifinfo_array, char *ip, char *ifname);

/**
 * @brief Checks whether a string denotes a IPv4 address
 * 
 * @param ip The IP in fromat x.y.z.q
 * @return true if the string is an IP, false otherwise 
 */
bool validate_ipv4_string(char *ip);
#endif