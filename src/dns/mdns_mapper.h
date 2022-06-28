/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of mdns mapper utils.
 */

#ifndef MDNS_MAPPER_H
#define MDNS_MAPPER_H

#include "mdns_list.h"

#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"
#include "../capture/middlewares/header_middleware/mdns_decoder.h"

/**
 * @brief MDNS connection structure
 *
 */
typedef struct hashmap_mdns_conn { /**< hashmap key */
  uint8_t key[IP_ALEN];
  struct mdns_list *value; /**< mDNS list structure */
  UT_hash_handle hh;       /**< hashmap handle */
} hmap_mdns_conn;

/**
 * @brief Inserts an mDNS query structure into the mdns mapper connection object
 *
 * @param imap mDNS mapper object
 * @param ip The IP
 * @param query mDNS query structure
 * @return 0 on success, -1 on failure
 */
int put_mdns_query_mapper(hmap_mdns_conn **imap, uint8_t *ip,
                          struct mdns_query_entry *query);

/**
 * @brief Inserts an mDNS answer structure into the mdns mapper connection
 * object
 *
 * @param imap mDNS mapper object
 * @param ip The IP
 * @param query mDNS answer structure
 * @return 0 on success, -1 on failure
 */
int put_mdns_answer_mapper(hmap_mdns_conn **imap, uint8_t *ip,
                           struct mdns_answer_entry *query);

/**
 * @brief Frees the mDNS mapper connection object
 *
 * @param hmap mDNS mapper connection object
 */
void free_mdns_mapper(hmap_mdns_conn **imap);

/**
 * @brief Checks if mDNS mapper has an element with a given request type
 *
 * @param imap mDNS mapper object
 * @param ip The IP
 * @param request The request type
 * @return 1 request present, 0 otherwise and -1 on failure
 */
int check_mdns_mapper_req(hmap_mdns_conn **imap, uint8_t *ip,
                          enum MDNS_REQUEST_TYPE request);
#endif
