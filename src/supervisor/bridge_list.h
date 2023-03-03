/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the bridge creation functions.
 */

#ifndef BRIDGE_LIST_H
#define BRIDGE_LIST_H

#include <net/ethernet.h>
#include <utarray.h>

#include "../utils/allocs.h"
#include "../utils/os.h"

/**
 * @brief The bridge MAc tuple definition
 *
 */
struct bridge_mac_tuple {
  uint8_t src_addr[ETHER_ADDR_LEN]; /**< MAC address in byte format for source
                                       node*/
  uint8_t dst_addr[ETHER_ADDR_LEN]; /**< MAC address in byte format for
                                       destination node*/
};
/**
 * @brief The MAC bridge address store circular doubly-linked list.
 */
struct bridge_mac_list {
  struct bridge_mac_list_entry *head; /**< head of the list*/
};

/**
 * @brief The MAC bridge address store doubly-linked list entry.
 */
struct bridge_mac_list_entry {
  struct bridge_mac_tuple mac_tuple;  /**< The MAC address tuple */
  struct bridge_mac_list_entry *prev; /* previous entry in doubly-linked list */
  struct bridge_mac_list_entry *next; /* nex entry in doubly-linked list */
};

/**
 * @brief The structure for edge definition
 *
 */
struct bridge_mac_list_tuple {
  struct bridge_mac_list_entry *left_edge;
  struct bridge_mac_list_entry *right_edge;
};

/**
 * @brief Init the MAC brideg address list for bridge assignment
 *
 * @return struct bridge_mac_list* The initialised list
 */
struct bridge_mac_list *init_bridge_list(void);

/**
 * @brief Free MAC bridge address list
 *
 * @param ml The MAC bridge address list
 */
void free_bridge_list(struct bridge_mac_list *ml);

/**
 * @brief Add bridge connection to the MAC bridge address list
 *
 * @param ml The MAC bridge address list
 * @param mac_addr_left The MAC address in byte format for left node
 * @param mac_addr_right The MAC address in byte format for right node
 * @return int 1 added if edge not present, 0 not added if edge present, -1 on
 * error
 */
int add_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left,
                   const uint8_t *mac_addr_right);

/**
 * @brief Removes a bridge connection from the MAC address list
 *
 * @param ml The MAC bridge address list
 * @param mac_addr_left The MAC address in byte format for left node
 * @param mac_addr_right The MAC address in byte format for right node
 * @return int 0 on success, -1 on error
 */
int remove_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left,
                      const uint8_t *mac_addr_right);

/**
 * @brief Get the bridge mac object from a bridge connection
 *
 * @param ml The MAC bridge address list
 * @param mac_addr_left The MAC address in byte format for left node
 * @param mac_addr_right The MAC address in byte format for rigth node
 * @return bridge_mac_list_tuple The MAC bridge edge element, structure elements
 * set to NULL if edge not found
 */
struct bridge_mac_list_tuple get_bridge_mac(struct bridge_mac_list *ml,
                                            const uint8_t *mac_addr_left,
                                            const uint8_t *mac_addr_right);

/**
 * @brief Get the MAC address dst list array for a src MAC address
 *
 * @param ml The MAC bridge address list
 * @param src_addr The source MAC address in byte format
 * @param mac_list_arr The returned array of MAC addresses
 * @return int The total number of tuples, -1 on error
 */
int get_src_mac_list(struct bridge_mac_list *ml, const uint8_t *src_addr,
                     UT_array **mac_list_arr);

/**
 * @brief Get the all the bridge edges as tuple list array
 *
 * @param ml The MAC bridge address list
 * @param tuple_list_arr The returned array of tuples
 * @return int The total number of tuples, -1 on error
 */
int get_all_bridge_edges(struct bridge_mac_list *ml, UT_array **tuple_list_arr);

/**
 * @brief Check if a bridge exist
 *
 * @param ml The MAC bridge address list
 * @param mac_addr_left The MAC address in byte format for left node
 * @param mac_addr_right The MAC address in byte format for rigth node
 * @return int 1 exists, 0 otherwise
 */
int check_bridge_exist(struct bridge_mac_list *ml, const uint8_t *mac_addr_left,
                       const uint8_t *mac_addr_right);
#endif
