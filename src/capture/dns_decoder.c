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
 * @brief File containing the implementation of the dns packet decoder
 * utilities.
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../utils/utarray.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/hash.h"

#include "capture_config.h"
#include "packet_decoder.h"

void decode_dns_questions(uint8_t *payload, struct capture_packet *cpac) {
  uint16_t idx, i = 0, j = 0;
  for (idx = 0; idx < /*cpac->dnss.nqueries*/ 1; idx++) {
    while ((((void *)&payload[i] - (void *)cpac->ethh)) < cpac->length) {
      if (payload[i] == '\0' || j + payload[i] >= MAX_QUESTION_LEN - 1)
        break;
      os_memcpy(&cpac->dnss.qname[j], &payload[i + 1], payload[i]);
      j += payload[i] + 1;
      i += payload[i] + 1;
      cpac->dnss.qname[j - 1] = '.';
    }
    j = (j) ? j - 1 : j;
    cpac->dnss.qname[j] = '\0';
  }
}

bool decode_dns_packet(struct capture_packet *cpac) {
  void *payload;
  int payload_offset = 0;
  int pos = 0;

  if ((void *)cpac->tcph != NULL && (void *)cpac->udph == NULL) {
    cpac->dnsh =
        (struct dns_header *)((void *)cpac->tcph + sizeof(struct tcphdr));
    payload_offset = 2;
  } else if ((void *)cpac->tcph == NULL && (void *)cpac->udph != NULL) {
    cpac->dnsh =
        (struct dns_header *)((void *)cpac->udph + sizeof(struct udphdr));
    payload_offset = 0;
  } else
    return false;

  cpac->dnsh_hash =
      md_hash((const char *)cpac->dnsh, sizeof(struct dns_header));

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

  pos = (int)((void *)cpac->dnsh - (void *)cpac->ethh);
  // We consider only the UDP encapsulation
  if (pos + payload_offset + sizeof(struct dns_header) <= cpac->length &&
      !payload_offset) {
    payload = (void *)cpac->dnsh + sizeof(struct dns_header);
    if (cpac->dnss.nqueries)
      decode_dns_questions((uint8_t *)payload, cpac);
  }

  // log_trace("DNS id=%d flags=0x%x nqueries=%d nanswers=%d nauth=%d nother=%d
  // qname=%s",
  //   cpac->dnss.tid, cpac->dnss.flags, cpac->dnss.nqueries,
  //   cpac->dnss.nanswers, cpac->dnss.nauth, cpac->dnss.nother,
  //   cpac->dnss.qname);

  return true;
}
