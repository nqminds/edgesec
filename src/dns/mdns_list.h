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
  enum MDNS_REQUEST_TYPE request;       /**< MDNS request type */
  uint32_t ttl;                         /**< MDNS ttl */
  uint16_t rrtype;                      /**< MDNS rrtype */
  uint16_t qtype;                       /**< MDNS qtype */
  char *name;                           /**< MDNS query/answer name */
};

/**
 * @brief MDNS info list
 * 
 */
struct mdns_list {
  struct mdns_list_info info;   /**< MDNS info structure */
  struct dl_list list;          /**< List definition */
};

/**
 * @brief Initialises and empty mdns list
 * 
 * @return struct mdns_list* Returned initialised empty mdns list
 */
struct mdns_list* init_mdns_list(void);

/**
 * @brief Pushes a mdns info entry in the mdns list
 * 
 * @param mlist The mdns list
 * @param info The mdns info structure
 * @return 0 on success, -1 on failure
 */
int push_mdns_list(struct mdns_list* mlist, struct mdns_list_info *info);

/**
 * @brief Delete a mdns list entry
 * 
 * @param el The mdns list entry
 */
void free_mdns_list_el(struct mdns_list* el);

/**
 * @brief Frees the mdns list
 * 
 * @param mlist The pointer to the mdns list
 */
void free_mdns_list(struct mdns_list* mlist);

/**
 * @brief Checks if MDNS list has an element with a given request type
 * 
 * @param mlist The pointer to the mdns list
 * @param request The request type
 * @return 1 request present, 0 otherwise and -1 on failure
 */
int has_mdns_list_request(struct mdns_list* mlist, enum MDNS_REQUEST_TYPE request);

#endif