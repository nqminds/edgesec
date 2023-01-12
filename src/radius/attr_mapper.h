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
  uint8_t key[ETHER_ADDR_LEN];
  struct hostapd_radius_attr *attr; /**< Radius attribute structure */
  UT_hash_handle hh;                /**< hashmap handle */
} attr_mac_conn;

/**
 * @brief Get the attribute structure for a given MAC address
 *
 * @param hmap Attribute mapper object
 * @param mac_addr MAC address in byte format
 * @param attr Output attribute structure address
 * @return int @c 1 if MAC address found, @c -1 error and @c 0 if MAC address
 * not found
 */
int get_attr_mapper(attr_mac_conn **hmap, uint8_t mac_addr[ETHER_ADDR_LEN],
                   struct hostapd_radius_attr **attr);

/**
 * @brief Insert an attribute structure into the attribute mapper connection object
 *
 * @param hmap Attribute mapper object
 * @param mac_addr MAC address in byte format
 * @param attr Input attribute structure address
 * @return int @c 0 on success, @c -1 otherwise
 */
int put_attr_mapper(attr_mac_conn **hmap, uint8_t mac_addr[ETHER_ADDR_LEN], struct hostapd_radius_attr *attr);

/**
 * @brief Frees the attribute structure
 *
 * @param attr Attribute structure
 */
void free_attr(struct hostapd_radius_attr *attr);

/**
 * @brief Frees the attribute mapper object
 *
 * @param hmap Attribute mapper object
 */
void free_attr_mapper(attr_mac_conn **hmap);
#endif
