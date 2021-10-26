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
 * @file ndpi_serialiser.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the ndpi serialiser utils.
 */

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

#include "capture_config.h"
#include "ndpi_serialiser.h"

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

ssize_t ndpi_serialise_meta(struct ndpi_detection_module_struct *ndpi_struct,
		  struct nDPI_flow_info * flow_info, struct alert_meta *meta, uint8_t **info)
{
  ndpi_serializer serializer;
  u_int32_t buffer_len = 0;
  char *serializer_buf = NULL;
  u_int16_t cli_score, srv_score;
  char *breed_name = NULL;
  char *category_name = NULL;
  struct ndpi_flow_struct *flow = flow_info->ndpi_flow;
  struct ndpi_proto l7_protocol = flow_info->detected_l7_protocol;

  *info = NULL;

  if (os_get_timestamp(&meta->timestamp) < 0) {
    log_trace("os_get_timestamp fail");
    return -1;
  }

  os_memset(&serializer, 0, sizeof(ndpi_serializer));

  os_memcpy(meta->src_mac_addr, flow_info->h_source, ETH_ALEN);
  os_memcpy(meta->dst_mac_addr, flow_info->h_dest, ETH_ALEN);

  ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_struct,
                           (l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN ? l7_protocol.app_protocol : l7_protocol.master_protocol));
  breed_name = ndpi_get_proto_breed_name(ndpi_struct, breed);
  
  if(l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    category_name = (char *)ndpi_category_get_name(ndpi_struct, l7_protocol.category);

  meta->risk = ndpi_risk2score(flow->risk, &cli_score, &srv_score);
  log_trace("risk score=%u client_score=%u server_score=%u", meta->risk, cli_score, srv_score);

  log_trace("breed=%s", breed_name);
  log_trace("category=%s", category_name);
  log_trace("source=" MACSTR " dest=" MACSTR, MAC2STR(flow_info->h_source), MAC2STR(flow_info->h_dest));

  if (ndpi_flow2json(ndpi_struct,
		   flow,
		   (flow_info->l3_type == L3_IP) ? 4 : 6,
		   flow_info->l4_protocol, 0,
		   flow_info->ip_tuple.v4.src, flow_info->ip_tuple.v4.dst,
		   (struct ndpi_in6_addr *) flow_info->ip_tuple.v6.src, (struct ndpi_in6_addr *) flow_info->ip_tuple.v6.dst,
		   flow_info->src_port, flow_info->dst_port,
		   l7_protocol, &serializer) > -1) {
    
    serializer_buf = ndpi_serializer_get_buffer(&serializer, &buffer_len);
    if ((*info = os_malloc(buffer_len)) == NULL) {
      log_err("os_malloc");
      ndpi_term_serializer(&serializer);
      return -1;
    }

    os_memcpy(*info, serializer_buf, buffer_len);
    ndpi_term_serializer(&serializer);
    return (ssize_t) buffer_len;
  }

  ndpi_term_serializer(&serializer);
  return 0;
}
