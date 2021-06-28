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
 * @file ndpi_serialiser.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the ndpi serialiser utils.
 */

#ifndef NDPI_SERIALISER_H
#define NDPI_SERIALISER_H

#include <netinet/if_ether.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

#include "capture_config.h"

#include "../utils/os.h"
#include "../utils/hash.h"

enum nDPI_l3_type {
  L3_IP, L3_IP6
};

struct nDPI_flow_info {
  uint32_t flow_id;
  unsigned long long int packets_processed;
  uint64_t first_seen;
  uint64_t last_seen;
  uint64_t hashval;

  uint8_t h_dest[ETH_ALEN];       /* destination eth addr */
  uint8_t h_source[ETH_ALEN];     /* source ether addr    */

  enum nDPI_l3_type l3_type;
  union {
    struct {
      uint32_t src;
      uint32_t dst;
    } v4;
    struct {
      uint64_t src[2];
      uint64_t dst[2];
    } v6;
  } ip_tuple;

  unsigned long long int total_l4_data_len;
  uint16_t src_port;
  uint16_t dst_port;

  uint8_t is_midstream_flow:1;
  uint8_t flow_fin_ack_seen:1;
  uint8_t flow_ack_seen:1;
  uint8_t detection_completed:1;
  uint8_t tls_client_hello_seen:1;
  uint8_t tls_server_hello_seen:1;
  uint8_t reserved_00:2;
  uint8_t l4_protocol;

  struct ndpi_proto detected_l7_protocol;
  struct ndpi_proto guessed_protocol;

  struct ndpi_flow_struct * ndpi_flow;
  struct ndpi_id_struct * ndpi_src;
  struct ndpi_id_struct * ndpi_dst;
};

struct nDPI_flow_meta {
  char src_mac_addr[MACSTR_LEN];
  char dst_mac_addr[MACSTR_LEN];
  char protocol[MAX_PROTOCOL_NAME_LEN];
  char hash[SHA256_HASH_LEN];
  char query[MAX_QUERY_LEN];
};

int ndpi_serialise_meta(struct ndpi_detection_module_struct *ndpi_struct,
		  struct nDPI_flow_info * flow_info, struct nDPI_flow_meta *meta);

#endif