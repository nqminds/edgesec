/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the mac mapper.
 */

#ifndef MAC_MAPPER_H
#define MAC_MAPPER_H

#include <inttypes.h>
#include <stdbool.h>

#include "bridge_list.h"

#include "../ap/ap_config.h"

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"
#include "../utils/hashmap.h"

#define MAX_DEVICE_LABEL_SIZE 255

/**
 * @brief MAC connection info structure
 *
 * MAC device = Device with a given MAC address
 */
struct mac_conn_info {
  enum AP_CONNECTION_STATUS status; /**< The MAC Connection status */
  int vlanid;                       /**< VLAN ID assigned to the MAC device */
  bool nat;              /**< Flag if set assigns NAT to the MAC device*/
  bool allow_connection; /**< If set allows the MAC device to connect ot the
                            network */
  uint8_t pass[AP_SECRET_LEN]; /**< WiFi password assigned to the MAC devices */
  ssize_t pass_len; /**< WiFi password length assigned to the MAC devices */
  char
      ip_addr[OS_INET_ADDRSTRLEN]; /**< IP address assigned to the MAC device */
  char ip_sec_addr[OS_INET_ADDRSTRLEN]; /**< The secondary IP address assigned
                               to the MAC device */
  char
      ifname[IFNAMSIZ]; /**< WiFi subnet interface assigned to the MAC device */
  char label[MAX_DEVICE_LABEL_SIZE]; /**< The MAC device label */
  char id[MAX_RANDOM_UUID_LEN];      /**< The MAC device ID */
  uint64_t join_timestamp;           /**< The MAC device AP join timestamp */
};

/**
 * @brief MAC connection structure
 *
 */
struct mac_conn {
  uint8_t mac_addr[ETH_ALEN]; /**< MAC address in byte format */
  struct mac_conn_info info;  /**< MAC connection structure */
};

/**
 * @brief MAC mapper connection structure
 *
 */
typedef struct hashmap_mac_conn { /**< hashmap key */
  char key[ETH_ALEN];
  struct mac_conn_info value; /**< MAC connection structure */
  UT_hash_handle hh;          /**< hashmap handle */
} hmap_mac_conn;

/**
 * @brief Get the MAC connection info structure for a given MAC address
 *
 * @param hmap MAC mapper object
 * @param mac_addr MAC address in byte format
 * @param info Output MAC connection info structure
 * @return int @c 1 if MAC address found, @c -1 error and @c 0 if MAC address
 * not found
 */
int get_mac_mapper(hmap_mac_conn **hmap, uint8_t mac_addr[ETH_ALEN],
                   struct mac_conn_info *info);

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

/**
 * @brief Generate a default mac info configuration
 *
 * @param info The input mac info structure
 * @param default_open_vlanid The default VLAN ID
 * @param allow_all_nat The NAT flag
 */
void init_default_mac_info(struct mac_conn_info *info, int default_open_vlanid,
                           bool allow_all_nat);

/**
 * @brief Get the MAC address for a given IP address
 *
 * @param hmap MAC mapper object
 * @param ip The AP address
 * @param mac_addr Output MAC address
 * @return int @c 1 if MAC address found, @c -1 error and @c 0 if MAC address
 * not found
 */
int get_ip_mapper(hmap_mac_conn **hmap, char *ip, uint8_t *mac_addr);
#endif
