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
 * @file mac_mapper.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the mac mapper.
 */

#ifndef MAC_MAPPER_H
#define MAC_MAPPER_H

#include <inttypes.h>
#include <stdbool.h>

#include "bridge_list.h"

#include "../ap/ap_config.h"

#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"
#include "../utils/hashmap.h"

/**
 * @brief MAC connection info structure
 * 
 * MAC device = Device with a given MAC address
 */
struct mac_conn_info {
  int       vlanid;                         /**< VLAN ID assigned to the MAC device */
  bool      nat;                            /**< Flag if set assigns NAT to the MAC device*/
  bool      allow_connection;               /**< If set allows the MAC device to connect ot the network */ 
	uint8_t 	pass[AP_SECRET_LEN];            /**< WiFi password assigned to the MAC devices */
	ssize_t		pass_len;                       /**< WiFi password length assigned to the MAC devices */
  char      ip_addr[IP_LEN];                /**< IP address assigned to the MAC device */
  char      ifname[IFNAMSIZ];               /**< WiFi subnet interface assigned to the MAC device */
};

/**
 * @brief MAC connection structure
 * 
 */
struct mac_conn {
  uint8_t mac_addr[ETH_ALEN];               /**< MAC address in byte format */
  struct mac_conn_info info;                /**< MAC connection structure */
};

/**
 * @brief MAC mapper connection structure
 * 
 */
typedef struct hashmap_mac_conn {           /**< hashmap key */
    char key[ETH_ALEN];               
    struct mac_conn_info value;             /**< MAC connection structure */
    UT_hash_handle hh;         		          /**< hashmap handle */
} hmap_mac_conn;

/**
 * @brief Create a MAC mapper connection object
 * 
 * @param connections Array of MAC connections
 * @param hmap Output MAC mapper object
 * @return true on success, false otherwise

 */
bool create_mac_mapper(UT_array *connections, hmap_mac_conn **hmap);


/**
 * @brief Get the MAC connection info structure for a given MAC address
 * 
 * @param hmap MAC mapper object
 * @param mac_addr MAC address in byte format
 * @param info Output MAC connection info structure
 * @return int @c 1 if MAc address found, @c -1 error and @c 0 if MAC address not found
 */
int get_mac_mapper(hmap_mac_conn **hmap, uint8_t mac_addr[ETH_ALEN], struct mac_conn_info *info);

/**
 * @brief Insert a MAC into the MAC mapper connection object
 * 
 * @param hmap MAC mapper object
 * @param conn MAC connection structure
 * @return true on success, false otherwise
 */
bool put_mac_mapper(hmap_mac_conn **hmap, struct mac_conn conn);

/**
 * @brief Frees the MAC mapper connection object
 * 
 * @param hmap MAC mapper connection object
 */
void free_mac_mapper(hmap_mac_conn **hmap);

/**
 * @brief Get the MAC list from the MAC mapper connection object
 * 
 * @param hmap MAC mapper connection object
 * @param list Output MAC list
 * @return int
 */
int get_mac_list(hmap_mac_conn **hmap, struct mac_conn **list);

#endif