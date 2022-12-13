/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the dns packet decoder
 * utilities.
 */

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <utarray.h>

#include "../../../utils/allocs.h"
#include "../../../utils/hash.h"
#include "../../../utils/os.h"

#include "packet_decoder.h"

void decode_dns_questions(uint8_t *payload, struct capture_packet *cpac) {
  uint16_t idx, i = 0, j = 0;
  for (idx = 0; idx < /*cpac->dnss.nqueries*/ 1; idx++) {
    while ((uint32_t)((&payload[i] - (uint8_t *)cpac->ethh)) < cpac->length) {
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
  ptrdiff_t payload_offset = 0;

  if (cpac->tcph != NULL && cpac->udph == NULL) {
    cpac->dnsh =
        (struct dns_header *)((char *)cpac->tcph + sizeof(struct tcphdr));
    payload_offset = 2;
  } else if (cpac->tcph == NULL && cpac->udph != NULL) {
    cpac->dnsh =
        (struct dns_header *)((char *)cpac->udph + sizeof(struct udphdr));
    payload_offset = 0;
  } else
    return false;

  strcpy(cpac->dnss.id, cpac->id);

  cpac->dnss.tid = ntohs(cpac->dnsh->tid);
  cpac->dnss.flags = ntohs(cpac->dnsh->flags);
  cpac->dnss.nqueries = ntohs(cpac->dnsh->nqueries);
  cpac->dnss.nanswers = ntohs(cpac->dnsh->nanswers);
  cpac->dnss.nauth = ntohs(cpac->dnsh->nauth);
  cpac->dnss.nother = ntohs(cpac->dnsh->nother);

  ptrdiff_t pos = ((char *)cpac->dnsh - (char *)cpac->ethh);
  // We consider only the UDP encapsulation
  if (pos + payload_offset + sizeof(struct dns_header) <= cpac->length &&
      !payload_offset) {
    void *payload = (char *)cpac->dnsh + sizeof(struct dns_header);
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
