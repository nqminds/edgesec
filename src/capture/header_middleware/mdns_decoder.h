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
 * @file mdns_decoder.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the mdns packet decoder utilities.
 */

#ifndef MDNS_DECODER_H
#define MDNS_DECODER_H

#include "../../utils/os.h"
#include "../../utils/utarray.h"

#include "packet_decoder.h"

struct mdns_query_entry {
  uint16_t qtype;
  char qname[MAX_WEB_PATH_LEN];
};

struct mdns_answer_entry {
  uint32_t ttl;
  uint16_t rrtype;
  char rrname[MAX_WEB_PATH_LEN];
  uint8_t ip[IP_ALEN];
};

/**
 * @brief Decodes the mdns queries
 *
 * @param payload The mdns payload
 * @param len The mdns payload length
 * @param first The starting index to the queries field
 * @param nqueries The number of queries
 * @param answers The queries array
 * @return 0 Success, -1 on failure
 */
int decode_mdns_queries(uint8_t *payload, size_t len, size_t *first,
                        uint16_t nqueries, UT_array *queries);

/**
 * @brief Decodes the mdns answers
 *
 * @param payload The mdns payload
 * @param len The mdns payload length
 * @param first The starting index to the answers field
 * @param nanswers The number of answers
 * @param answers The answers array
 * @return 0 Success, -1 on failure
 */
int decode_mdns_answers(uint8_t *payload, size_t len, size_t *first,
                        uint16_t nanswers, UT_array *answers);

/**
 * @brief Decodes the mdns header
 *
 * @param packet The mdns packet
 * @param out The output mdns decoded header
 * @return 0 Success, -1 on failure
 */
int decode_mdns_header(uint8_t *packet, struct mdns_header *out);

/**
 * @brief Decode mdns packet
 *
 * @param cpac The capture packet structure
 * @return true Success, false otherwise
 */
bool decode_mdns_packet(struct capture_packet *cpac);
#endif
