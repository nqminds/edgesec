/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the mdns packet decoder utilities.
 */

#ifndef MDNS_DECODER_H
#define MDNS_DECODER_H

#include <utarray.h>
#include "../../../utils/net.h"
#include "../../../utils/os.h"

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
 * @param[in,out] first The starting index to the queries field in the mdns @p
 * payload. When done, this will be modified to be the starting index of the
 * next field.
 * @param nqueries The number of queries
 * @param[in,out] queries The ::mdns_query_entry queries array
 * @return 0 Success, -1 on failure
 */
int decode_mdns_queries(uint8_t *payload, size_t len, size_t *first,
                        uint16_t nqueries, UT_array *queries);

/**
 * @brief Decodes the mdns answers
 *
 * @param payload The mdns payload
 * @param len The mdns payload length
 * @param[in,out] first The starting index to the answers field in the mdns @p
 * payload. When done, this will be modified to be the starting index of the
 * next field.
 * @param nanswers The number of answers
 * @param[in,out] answers The ::mdns_answer_entry answers array
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
