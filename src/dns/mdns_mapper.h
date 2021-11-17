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
 * @file mdns_mapper.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of mdns mapper utils.
 */

#ifndef MDNS_MAPPER_H
#define MDNS_MAPPER_H

#include "mdns_list.h"

#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"
#include "../capture/mdns_decoder.h"

/**
 * @brief MDNS connection structure
 * 
 */
typedef struct hashmap_mdns_conn {            /**< hashmap key */
    char key[IP_ALEN];               
    struct mdns_list* value;                /**< mDNS list structure */
    UT_hash_handle hh;         		        /**< hashmap handle */
} hmap_mdns_conn;

/**
 * @brief Insert a mDNS query structure into the mdns mapper connection object
 * 
 * @param imap mDNS mapper object
 * @param query The IP
 * @param query mDNS query structure
 * @return 0 on success, -1 on failure
 */
int put_mdns_query_mapper(hmap_mdns_conn **imap, uint8_t *ip, struct mdns_query_entry *query);

/**
 * @brief Insert a mDNS answer structure into the mdns mapper connection object
 * 
 * @param imap mDNS mapper object
 * @param query The IP
 * @param query mDNS answer structure
 * @return 0 on success, -1 on failure
 */
int put_mdns_answer_mapper(hmap_mdns_conn **imap, uint8_t *ip, struct mdns_answer_entry *query);

/**
 * @brief Frees the mDNS mapper connection object
 * 
 * @param hmap mDNS mapper connection object
 */
void free_mdns_mapper(hmap_mdns_conn **imap);

#endif