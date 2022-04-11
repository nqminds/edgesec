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
 * @file iface_mapper.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the interface mapper utilities.
 */

#ifndef IFACE_MAPPER_H_
#define IFACE_MAPPER_H_

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "utarray.h"
#include "uthash.h"
#include "allocs.h"
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
	char 			ip_addr[IP_LEN];					/**< Interface string IP4 address */
	char 			ip_addr6[OS_INET6_ADDRSTRLEN];		/**< Interface string IP6 address */
	char 			peer_addr[IP_LEN];					/**< Interface string peer IP address */
	char 			brd_addr[IP_LEN];					/**< Interface string IP broadcast address */
	uint8_t 		mac_addr[ETH_ALEN];					/**< Interface byte MAC address */
} netif_info_t;

/**
 * @brief Interface configuration info structure
 *
 */
typedef struct config_ifinfo_t{
  int       				vlanid;                 /**< Interface VLAN ID */
  char 						ifname[IFNAMSIZ];		/**< Interface string name */
  char 						brname[IFNAMSIZ];		/**< Bridge string name */
  char 						ip_addr[IP_LEN];		/**< Interface string IP address */
  char 						brd_addr[IP_LEN];		/**< Interface string IP broadcast address */
  char 						subnet_mask[IP_LEN];	/**< Interface string IP subnet mask */
} config_ifinfo_t;

/**
 * @brief Subnet to interface connection mapper
 *
 */
typedef struct hashmap_if_conn {
    in_addr_t 				key;               		/**< key as subnet */
    char 						  value[IFNAMSIZ];		/**< value as the interface name */
    UT_hash_handle 		hh;         		    /**< makes this structure hashable */
} hmap_if_conn;

/**
 * @brief MAC connection structure
 *
 */
struct vlan_conn {
  int 	vlanid;								/**< the VLAN ID */
  char 	ifname[IFNAMSIZ];					/**< the interface name */
  pid_t analyser_pid;                		/**< Analyser process descriptor */
};

/**
 * @brief VLAN to interface connection mapper
 *
 */
typedef struct hashmap_vlan_conn {
    int 						key;               		/**< VLAN id as subnet */
	struct vlan_conn			value;					/**< value as the vlan_conn structure */
    UT_hash_handle 				hh;         		    /**< makes this structure hashable */
} hmap_vlan_conn;

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
 * @brief Get the vlan connection structure corresponding to a VLAN ID
 *
 * @param hmap The VLAN ID to vlan connection mapper object
 * @param vlanid The VLAN ID
 * @param conn The returned VLAN connection structure
 * @return int 1 if found, 0 not found, -1 on error
 */
int get_vlan_mapper(hmap_vlan_conn **hmap, int vlanid, struct vlan_conn	*conn);

/**
 * @brief Inserts a vlan connection structure and VLAN ID value into the interface connection mapper
 *
 * @param hmap The VLAN ID to interface connection mapper object
 * @param conn The VLAN connection structure
 * @return true on success, false otherwise
 */
bool put_vlan_mapper(hmap_vlan_conn **hmap, struct vlan_conn *conn);

/**
 * @brief Frees the VLAN ID to interface connection mapper object
 *
 * @param hmap The VLAN ID to interface connection mapper object
 */
void free_vlan_mapper(hmap_vlan_conn **hmap);

/**
 * @brief Get the interface name from an IP string
 *
 * @param config_ifinfo_array The list of IP subnets
 * @param ip The input IP address
 * @param ifname The returned interface name (buffer has to be preallocated)
 * @return 0 on success, -1 otherwise
 */
int get_ifname_from_ip(UT_array *config_ifinfo_array, char *ip, char *ifname);

/**
 * @brief Get the bridge name from an IP string
 *
 * @param config_ifinfo_array The list of IP subnets
 * @param ip The input IP address
 * @param ifname The returned interface name (buffer has to be preallocated)
 * @return 0 on success, -1 otherwise
 */
int get_brname_from_ip(UT_array *config_ifinfo_array, char *ip_addr, char *brname);

/**
 * @brief Create the subnet to interface mapper
 *
 * @param config_ifinfo_array The connection info array
 * @param hmap The subnet to interface mapper
 * @return true on success, false otherwise
 */
bool create_if_mapper(UT_array *config_ifinfo_array, hmap_if_conn **hmap);

/**
 * @brief Create the VLAN ID to interface mapper
 *
 * @param config_ifinfo_array The connection info array
 * @param hmap The VLAN ID to interface mapper
 * @return true on success, false otherwise
 */
bool create_vlan_mapper(UT_array *config_ifinfo_array, hmap_vlan_conn **hmap);

/**
 * @brief Initialise the interface names
 *
 * @param config_ifinfo_array The connection info array
 * @param ifname The interface name prefix
 * @param brname The bridge name prefix
 * @return 0 on success, -1 otherwise
 */
int init_ifbridge_names(UT_array *config_ifinfo_array, char *ifname, char *brname);
#endif
