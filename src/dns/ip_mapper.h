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
 * @file ip_mapper.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of ip mapper utils.
 */

#ifndef IP_MAPPER_H
#define IP_MAPPER_H

#include "mdns_list.h"

#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"

/**
 * @brief MAC IP connection structure
 * 
 */
typedef struct hashmap_ip_conn {            /**< hashmap key */
    char key[IP_ALEN];               
    struct mdns_list* value;                /**< mDNS list structure */
    UT_hash_handle hh;         		        /**< hashmap handle */
} hmap_ip_conn;

#endif