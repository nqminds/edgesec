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
 * @brief The MAC address store list
 * 
 */
struct bridge_mac_list {
  char mac_addr[ETH_ALEN];        /**< MAC address in byte format */
  struct dl_list list;            /**< List definition */
};

/**
 * @brief Init the MAC address list for bridge assignment (WIP)
 * 
 * @return struct bridge_mac_list* The initialised list (WIP)
 */
struct bridge_mac_list *init_bridge_list(void);

/**
 * @brief Free MAC address list (WIP)
 * 
 * @param ml The MAC address list (WIP)
 */
void free_bridge_list(struct bridge_mac_list *ml);

/**
 * @brief Add a MAC address to the MAC address list (WIP)
 * 
 * @param ml The MAC address list (WIP)
 * @param mac_addr The MAC address in byte format to be added (WIP)
 * @return int (WIP)
 */
int add_bridge_mac(struct bridge_mac_list *ml, const char *mac_addr);

/**
 * @brief WIP
 * 
 * @param ml 
 * @param mac_addr 
 */
void remove_bridge_mac(struct bridge_mac_list *ml, const char *mac_addr);

#endif