/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file mdns_list.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of mdns list utils.
 */

#ifndef MDNS_LIST_H
#define MDNS_LIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "../utils/list.h"

enum MDNS_REQUEST_TYPE {
  MDNS_REQUEST_NONE = 0,
  MDNS_REQUEST_QUERY,
  MDNS_REQUEST_ANSWER,
};

/**
 * @brief MDNS info list
 *
 */
struct mdns_list_info {
  enum MDNS_REQUEST_TYPE request; /**< MDNS request type */
  uint32_t ttl;                   /**< MDNS ttl */
  uint16_t rrtype;                /**< MDNS rrtype */
  uint16_t qtype;                 /**< MDNS qtype */
  char *name;                     /**< MDNS query/answer name */
};

/**
 * @brief MDNS info list
 *
 */
struct mdns_list {
  struct mdns_list_info info; /**< MDNS info structure */
  struct dl_list list;        /**< List definition */
};

/**
 * @brief Initialises an empty mdns list
 *
 * @return struct mdns_list* Returned initialised empty mdns list
 */
struct mdns_list *init_mdns_list(void);

/**
 * @brief Pushes an mdns info entry in the mdns list
 *
 * @param mlist The mdns list
 * @param info The mdns info structure
 * @return 0 on success, -1 on failure
 */
int push_mdns_list(struct mdns_list *mlist, struct mdns_list_info *info);

/**
 * @brief Delete a mdns list entry
 *
 * @param el The mdns list entry
 */
void free_mdns_list_el(struct mdns_list *el);

/**
 * @brief Frees the mdns list
 *
 * @param mlist The pointer to the mdns list
 */
void free_mdns_list(struct mdns_list *mlist);

/**
 * @brief Checks if MDNS list has an element with a given request type
 *
 * @param mlist The pointer to the mdns list
 * @param request The request type
 * @return 1 request present, 0 otherwise and -1 on failure
 */
int check_mdns_list_req(struct mdns_list *mlist,
                        enum MDNS_REQUEST_TYPE request);

#endif
