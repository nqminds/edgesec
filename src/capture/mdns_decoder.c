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
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/hash.h"
#include "../utils/squeue.h"

#include "capture_config.h"
#include "packet_decoder.h"

#define COMPRESSION_FLAG 0xC0

int decode_mdns_subquery(uint8_t *start, char **out)
{
  size_t len;
  char *qname = NULL;

  *out = NULL;

  if ((qname = os_zalloc(start[0] + 2)) == NULL) {
    log_err("os_zalloc");
    return -1;
  }

  if (start[0]) {
    strncpy(qname, (char *)&start[1], start[0]);
  }

  qname[start[0]] = '.';

  log_trace(">>>>%d %x", start[0], start[1]);
  *out = qname;

  return 0;
}

int decode_mdns_queries(uint8_t *payload, size_t len, uint16_t nqueries, char **out)
{
  uint16_t idx, i = 0, j = 0;
  size_t buf_len = 0;
  uint8_t *start = payload;
  char *qname = NULL;
  struct string_queue* squeue = NULL;

  *out = NULL;

  if ((squeue = init_string_queue(-1)) == NULL) {
    log_trace("init_string_queue fail");
    return -1;
  }

  for (idx = 0; idx < nqueries; idx++) {
    while (i < len) {
      if (start[i] == '\0') {
        log_trace("HERE");
        break;
      }

      j = (start[i] & COMPRESSION_FLAG) ? start[i] & (~COMPRESSION_FLAG) : i;

      if (decode_mdns_subquery(&start[j], &qname) < 0) {
        log_trace("decode_mdns_subquery fail");
        free_string_queue(squeue);
        return -1;
      }

      if (qname != NULL && push_string_queue(squeue, qname) < 0) {
        log_trace("push_string_queue fail");
        os_free(qname);
        free_string_queue(squeue);
        return -1;
      }

      log_trace("-->[%d] %s %d", start[i] & COMPRESSION_FLAG, qname, strlen(qname));
      os_free(qname);

      if (start[i] & COMPRESSION_FLAG) {
        break;
      }

      i += start[i] + 1;
    }

    i += sizeof(struct mdns_query_meta) + 1;

    if (push_string_queue(squeue, " ") < 0) {
      log_trace("push_string_queue fail");
      free_string_queue(squeue);
      return -1;
    }
    log_trace("+++++++++++ %d", idx);
  }

  *out = concat_string_queue(squeue, -1);
  free_string_queue(squeue);
  return 0;
}

int decode_mdns_header(uint8_t *packet, struct mdns_header *out)
{
  struct mdns_header *mdnsh = (struct mdns_header *) packet;

  out->tid = ntohs(mdnsh->tid);
  out->flags = ntohs(mdnsh->flags);
  out->nqueries = ntohs(mdnsh->nqueries);
  out->nanswers = ntohs(mdnsh->nanswers);
  out->nauth = ntohs(mdnsh->nauth);
  out->nother = ntohs(mdnsh->nother);

  return 0;
}

bool decode_mdns_packet(struct capture_packet *cpac)
{
  struct mdns_header mdnsh;
  size_t payload_len;
  void *payload;
  int pos = 0;
  char *qname = NULL;

  if ((void *)cpac->udph != NULL) {
    cpac->mdnsh = (struct mdns_header *) ((void *)cpac->udph + sizeof(struct udphdr));
  } else
    return false;

  cpac->mdnsh_hash = md_hash((const char*) cpac->mdnsh, sizeof(struct mdns_header));

  cpac->mdnss.hash = cpac->mdnsh_hash;
  cpac->mdnss.timestamp = cpac->timestamp;
  cpac->mdnss.ethh_hash = cpac->ethh_hash;
  strcpy(cpac->mdnss.id, cpac->id);

  if (decode_mdns_header((uint8_t *)cpac->mdnsh, &mdnsh) < 0) {
    return false;
  }

  cpac->mdnss.tid = mdnsh.tid;
  cpac->mdnss.flags = mdnsh.flags;
  cpac->mdnss.nqueries = mdnsh.nqueries;
  cpac->mdnss.nanswers = mdnsh.nanswers;
  cpac->mdnss.nauth = mdnsh.nauth;
  cpac->mdnss.nother = mdnsh.nother;

// while ((((void *)&payload[i] - (void*)cpac->ethh)) < cpac->length) {
  pos = (int)((void*)cpac->mdnsh - (void*)cpac->ethh);
  if (pos + sizeof(struct dns_header) <= cpac->length) {
    payload = (void*)cpac->mdnsh + sizeof(struct mdns_header);
    payload_len = ((void*) cpac->ethh + cpac->length) - (void *) payload;
    if (cpac->mdnss.nqueries) {
      if (decode_mdns_queries(payload, payload_len, cpac->mdnss.nqueries, &qname) < 0) {
        log_trace("decode_mdns_questions fail");
        return false;
      }
      strncpy(cpac->mdnss.qname, qname, MAX_QUESTION_LEN);
      os_free(qname);
    }
  }
  
  log_trace("mDNS id=%d flags=0x%x nqueries=%d nanswers=%d nauth=%d nother=%d qname=%s",
    cpac->mdnss.tid, cpac->mdnss.flags, cpac->mdnss.nqueries, cpac->mdnss.nanswers,
    cpac->mdnss.nauth, cpac->mdnss.nother, cpac->mdnss.qname);

  return true;
}
