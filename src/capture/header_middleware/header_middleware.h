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
 * @file header_middleware.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the header middleware utilities.
 */

#ifndef HEADER_MIDDLEWARE_H
#define HEADER_MIDDLEWARE_H

#include <pcap.h>
#include <stdint.h>

#include "../../utils/allocs.h"
#include "../../utils/os.h"

#include "../capture_config.h"

#include "packet_queue.h"
#include "../pcap_service.h"

/**
 * @brief Initialises the header middleware
 *
 * @param db The sqlite3 db
 * @param eloop The eloop structure
 * @param pc The pcap context
 * @return struct middleware_context* the middleware context on success, NULL on
 * failure
 */
struct middleware_context *init_header_middleware(sqlite3 *db,
                                                  struct eloop_data *eloop,
                                                  struct pcap_context *pc);

/**
 * @brief Header packet processors
 *
 * @param context The middleware context
 * @param ltype The packet type
 * @param header The pcap packet header
 * @param packet The pcap packet
 * @param ifname The capture interface
 * @return int 0 on success, -1 on failure
 */
int process_header_middleware(struct middleware_context *context, char *ltype,
                              struct pcap_pkthdr *header, uint8_t *packet,
                              char *ifname);

/**
 * @brief Frees the middleware context
 *
 * @param context The middleware context
 */
void free_header_middleware(struct middleware_context *context);

#endif
