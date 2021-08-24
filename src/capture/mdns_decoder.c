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
 * @file mdns_decoder.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the mdns packet decoder utilities.
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

void decode_mdns_questions(uint8_t *payload, struct capture_packet *cpac)
{
  uint16_t idx, i = 0, j = 0;
  for (idx = 0; idx < /*cpac->dnss.nqueries*/1; idx++) {
    while ((((void *)&payload[i] - (void*)cpac->ethh)) < cpac->length) {
      if (payload[i] == '\0' || j + payload[i] >= MAX_QUESTION_LEN - 1)
        break;
      os_memcpy(&cpac->mdnss.qname[j], &payload[i + 1], payload[i]);
      j += payload[i] + 1;
      i += payload[i] + 1;
      cpac->mdnss.qname[j - 1] = '.';
    }
    j = (j) ? j - 1 : j;
    cpac->mdnss.qname[j] = '\0';
  }
}

bool decode_mdns_packet(struct capture_packet *cpac)
{
  void *payload;
  int pos = 0;

  if ((void *)cpac->udph != NULL) {
    cpac->mdnsh = (struct mdns_header *) ((void *)cpac->udph + sizeof(struct udphdr));
  } else
    return false;

  cpac->mdnsh_hash = md_hash((const char*) cpac->mdnsh, sizeof(struct mdns_header));

  cpac->mdnss.hash = cpac->mdnsh_hash;
  cpac->mdnss.timestamp = cpac->timestamp;
  cpac->mdnss.ethh_hash = cpac->ethh_hash;
  strcpy(cpac->mdnss.id, cpac->id);

  cpac->mdnss.tid = ntohs(cpac->mdnsh->tid);
  cpac->mdnss.flags = ntohs(cpac->mdnsh->flags);
  cpac->mdnss.nqueries = ntohs(cpac->mdnsh->nqueries);
  cpac->mdnss.nanswers = ntohs(cpac->mdnsh->nanswers);
  cpac->mdnss.nauth = ntohs(cpac->mdnsh->nauth);
  cpac->mdnss.nother = ntohs(cpac->mdnsh->nother);

  pos = (int)((void*)cpac->mdnsh - (void*)cpac->ethh);
  if (pos + sizeof(struct dns_header) <= cpac->length) {
    payload = (void*)cpac->mdnsh + sizeof(struct mdns_header);
    if (cpac->mdnss.nqueries)
        decode_mdns_questions((uint8_t *)payload, cpac);
  }
  
  log_trace("mDNS id=%d flags=0x%x nqueries=%d nanswers=%d nauth=%d nother=%d qname=%s",
    cpac->mdnss.tid, cpac->mdnss.flags, cpac->mdnss.nqueries, cpac->mdnss.nanswers,
    cpac->mdnss.nauth, cpac->mdnss.nother, cpac->mdnss.qname);

  return true;
}
