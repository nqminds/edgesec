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
 * @file dns_decoder.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the dns packet decoder utilities.
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../utils/utarray.h"
#include "../utils/os.h"
#include "../utils/hash.h"

#include "capture_config.h"
#include "packet_decoder.h"

typedef struct dns_question {
    char *name;
    uint16_t type;
    uint16_t cls;
    struct dns_question *next;
} dns_question;

void decode_dns_questions(uint8_t *payload, struct capture_packet *cpac)
{
  uint16_t idx;
  for (idx = 0; idx < cpac->dnss.nqueries; idx++) {
    log_trace("Question %d", idx);
  }
}

void decode_dns_flags(uint16_t flags, struct dns_schema *dnss)
{
//   dnss->p_id = (payload[0] << 8) | payload[1];
//   dnss->p_qr = (payload[2] >> 7) & 1;
//   dnss->p_aa = (payload[2] >> 2) & 1;
//   dnss->p_tc = (payload[2] >> 1) & 1;
//   dnss->p_rd = (payload[2] >> 0) & 1;
//   dnss->p_ra = (payload[3] >> 7) & 1;
//   dnss->p_z = (payload[3] >> 4) & 7;
//   dnss->p_opcode = (payload[2] >> 3) & 0xf;
//   dnss->p_rcode = (payload[3] >> 0) & 0xf;
  
}

bool decode_dns_packet(struct capture_packet *cpac)
{
  void *payload;
  int payload_offset = 0;
  int pos = 0;

  if ((void *)cpac->tcph != NULL && (void *)cpac->udph == NULL) {
    cpac->dnsh = (struct dns_header *) ((void *)cpac->tcph + sizeof(struct tcphdr));
    payload_offset = 2;
  } else if ((void *)cpac->tcph == NULL && (void *)cpac->udph != NULL) {
    cpac->dnsh = (struct dns_header *) ((void *)cpac->udph + sizeof(struct udphdr));
    payload_offset = 0;
  } else
    return false;

  cpac->dnsh_hash = md_hash((const char*) cpac->dnsh, sizeof(struct dns_header));

  cpac->dnss.hash = cpac->dnsh_hash;
  cpac->dnss.timestamp = cpac->timestamp;
  cpac->dnss.ethh_hash = cpac->ethh_hash;
  strcpy(cpac->dnss.id, cpac->id);

  cpac->dnss.tid = ntohs(cpac->dnsh->tid);
  cpac->dnss.flags = ntohs(cpac->dnsh->flags);
  cpac->dnss.nqueries = ntohs(cpac->dnsh->nqueries);
  cpac->dnss.nanswers = ntohs(cpac->dnsh->nanswers);
  cpac->dnss.nauth = ntohs(cpac->dnsh->nauth);
  cpac->dnss.nother = ntohs(cpac->dnsh->nother);

  pos = (int)((void*)cpac->dnsh - (void*)cpac->ethh);
  // We consider only the UDP encapsulation
  if (pos + payload_offset + sizeof(struct dns_header) <= cpac->length && !payload_offset) {
    payload = (void*)cpac->dnsh + sizeof(struct dns_header);
    decode_dns_questions((uint8_t *)payload, cpac);
  }
  
  log_trace("DNS id=%d flags=0x%x nqueries=%d nanswers=%d nauth=%d nother=%d",
    cpac->dnss.tid, cpac->dnss.flags, cpac->dnss.nqueries, cpac->dnss.nanswers,
    cpac->dnss.nauth, cpac->dnss.nother);

  return true;
}
