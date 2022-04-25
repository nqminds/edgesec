/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file reflection_list.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of reflection list structures.
 */

#ifndef REFLECTION_LIST_H
#define REFLECTION_LIST_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>

#include "../utils/list.h"

struct reflection_list {
  int recv_fd;
  int send_fd;
  unsigned int ifindex;
  char ifname[IFNAMSIZ];
  struct dl_list list; /**< List definition */
};

/**
 * @brief Initialises the reflection list
 *
 * @return struct reflection_list * The reflection list or %NULL on failure
 */
struct reflection_list *init_reflection_list(void);

/**
 * @brief Pushes an interface element to the reflection list
 *
 * @param rif The reflection list
 * @param ifindex The interface index
 * @param ifname The interface name
 * @return struct reflection_list* Returned the interface list element, NULL on
 * failure
 */
struct reflection_list *push_reflection_list(struct reflection_list *rif,
                                             unsigned int ifindex,
                                             const char *ifname);

/**
 * @brief Frees the reflection list
 *
 * @param rif The reflection list
 */
void free_reflection_list(struct reflection_list *rif);

#endif // REFLECTION_ZONE_H
