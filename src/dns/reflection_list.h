/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of reflection list structures.
 */

#ifndef REFLECTION_LIST_H
#define REFLECTION_LIST_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

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
