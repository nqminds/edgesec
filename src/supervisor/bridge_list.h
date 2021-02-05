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
 * @file bridge_list.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the bridge creation functions.
 */

#ifndef BRIDGE_LIST_H
#define BRIDGE_LIST_H

#include "../utils/list.h"
#include "../utils/os.h"

/**
 * @brief The bridge MAc tuple definition
 * 
 */
struct bridge_mac_tuple {
  uint8_t left_addr[ETH_ALEN];            /**< MAC address in byte format for left node*/
  uint8_t right_addr[ETH_ALEN];           /**< MAC address in byte format for right node*/
};
/**
 * @brief The MAC bridge address store list
 * 
 */
struct bridge_mac_list {
  struct bridge_mac_tuple mac_tuple;          /**< The MAC address tuple */
  struct dl_list list;                        /**< List definition */
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
 * @return int 0 on success, -1 on error
 */
int add_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right);

/**
 * @brief Removes a bridge connection from the MAC address list
 * 
 * @param ml The MAC bridge address list
 * @param mac_addr_left The MAC address in byte format for left node
 * @param mac_addr_right The MAC address in byte format for right node
 * @return int 0 on success, -1 on error
 */
int remove_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right);

/**
 * @brief Get the bridge mac object from a brideg connection
 * 
 * @param ml The MAC bridge address list
 * @param mac_addr_left The MAC address in byte format for left node
 * @param mac_addr_right The MAC address in byte format for rigth node
 * @return struct bridge_mac_list* The MAC bridge element, NULL if not found
 */
struct bridge_mac_list *get_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right);

/**
 * @brief Get the bridge tuple list array
 * 
 * @param ml The MAC bridge address list
 * @param tuple_list The returned list of tuples
 * @return int The total number of tuples
 */
int get_bridge_tuple_list(struct bridge_mac_list *ml, struct bridge_mac_tuple **tuple_list);

#endif