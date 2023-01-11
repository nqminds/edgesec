/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the Radius attributes mapper.
 */

#ifndef ATTR_MAPPER_H
#define ATTR_MAPPER_H

#include <stdbool.h>
#include <inttypes.h>
#include <utarray.h>
#include <uthash.h>

#include "../utils/hashmap.h"
#include "../utils/os.h"

/**
 * @brief Radius attribute mapper structure
 *
 */
typedef struct attr_mac_conn { /**< hashmap key */
  char key[ETHER_ADDR_LEN];
  struct hostapd_radius_attr *attr; /**< Radius attribute structure */
  UT_hash_handle hh;                /**< hashmap handle */
} hmap_mac_conn;

/**
 * @brief Get the attribute structure for a given MAC address
 *
 * @param hmap Attribute mapper object
 * @param mac_addr MAC address in byte format
 * @param attr Output attribute structure address
 * @return int @c 1 if MAC address found, @c -1 error and @c 0 if MAC address
 * not found
 */
int get_attr_mapper(hmap_mac_conn **hmap, uint8_t mac_addr[ETHER_ADDR_LEN],
                   struct hostapd_radius_attr **attr);

/**
 * @brief Insert an attribute structure into the attribute mapper connection object
 *
 * @param hmap Attribute mapper object
 * @param mac_addr MAC address in byte format
 * @param attr Intput attribute structure address
 * @return int @c 0 on success, @c -1 otherwise
 */
int put_attr_mapper(hmap_mac_conn **hmap, uint8_t mac_addr[ETHER_ADDR_LEN], struct hostapd_radius_attr *attr);

/**
 * @brief Frees the MAC mapper connection object
 *
 * @param hmap MAC mapper connection object
 */
void free_mac_mapper(hmap_mac_conn **hmap);
#endif
