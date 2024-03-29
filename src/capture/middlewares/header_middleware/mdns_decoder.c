/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the mdns packet decoder
 * utilities.
 */

#include <netinet/udp.h>

#include "../../../utils/allocs.h"
#include "../../../utils/hash.h"
#include "../../../utils/iface.h"
#include "../../../utils/os.h"
#include "../../../utils/squeue.h"

#include "mdns_decoder.h"
#include "packet_decoder.h"

#define COMPRESSION_FLAG 0xC0
#define COMPRESSION_FLAG_BIT7 0x80
#define COMPRESSION_FLAG_BIT6 0x40

int copy_mdns_query_name(uint8_t *start, char **out) {
  char *qname = NULL;

  *out = NULL;

  if (!start[0]) {
    return 0;
  }

  if ((qname = os_zalloc(start[0] + 2)) == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  strncpy(qname, (char *)&start[1], start[0]);

  qname[start[0]] = '.';

  *out = qname;

  return 0;
}

uint16_t get_mdns_query_offset(uint8_t low, uint8_t high) {
  uint16_t offset = low;
  offset <<= 8;
  return offset | high;
}

int decode_mdns_query_name(uint8_t *payload, size_t len, size_t *first,
                           char **out) {
  size_t i = *first, off;
  char *qname = NULL;
  struct string_queue *squeue = NULL;

  *out = NULL;

  if ((squeue = init_string_queue(-1)) == NULL) {
    log_trace("init_string_queue fail");
    return -1;
  }

  while (i < len) {
    if (payload[i] == '\0') {
      break;
    }

    if ((payload[i] & COMPRESSION_FLAG_BIT7) &&
        (payload[i] & COMPRESSION_FLAG_BIT6)) {
      off = (size_t)get_mdns_query_offset(payload[i] & (~COMPRESSION_FLAG),
                                          payload[i + 1]);

      if (decode_mdns_query_name(payload, len, &off, &qname) < 0) {
        log_trace("decode_mdns_query_ptr fail");
        free_string_queue(squeue);
        return -1;
      }
      if (qname != NULL) {
        if (push_string_queue(squeue, qname) < 0) {
          log_trace("push_string_queue fail");
          os_free(qname);
          free_string_queue(squeue);
          return -1;
        }
        os_free(qname);
      }
      i += 1;
      break;
    } else {
      if (copy_mdns_query_name(&payload[i], &qname) < 0) {
        log_trace("decode_mdns_subquery fail");
        free_string_queue(squeue);
        return -1;
      }

      if (qname != NULL) {
        if (push_string_queue(squeue, qname) < 0) {
          log_trace("push_string_queue fail");
          os_free(qname);
          free_string_queue(squeue);
          return -1;
        }
        os_free(qname);
      }
      i += payload[i] + 1;
    }
  }

  *first = i;
  *out = concat_string_queue(squeue, -1);

  free_string_queue(squeue);
  return 0;
}

int decode_mdns_queries(uint8_t *payload, size_t len, size_t *first,
                        uint16_t nqueries, UT_array *queries) {
  int idx;
  size_t i = *first;
  char *qname = NULL;
  struct mdns_query_meta *meta;
  struct mdns_query_entry entry;

  for (idx = 0; idx < nqueries; idx++) {
    if (decode_mdns_query_name(payload, len, &i, &qname) < 0) {
      log_trace("decode_mdns_query_ptr fail");
      return -1;
    }

    i++;
    meta = (struct mdns_query_meta *)&payload[i];
    i += sizeof(struct mdns_query_meta);

    if (qname != NULL) {
      entry.qtype = ntohs(meta->qtype);
      strcpy(entry.qname, qname);
      utarray_push_back(queries, &entry);
      os_free(qname);
    }
  }

  *first = i;
  return 0;
}

int decode_mdns_answers(uint8_t *payload, size_t len, size_t *first,
                        uint16_t nanswers, UT_array *answers) {
  int idx;
  size_t i = *first;
  char *rrname = NULL;
  struct mdns_answer_meta *meta;
  struct mdns_answer_entry entry;

  for (idx = 0; idx < nanswers; idx++) {
    if (decode_mdns_query_name(payload, len, &i, &rrname) < 0) {
      log_trace("decode_mdns_query_ptr fail");
      return -1;
    }

    i++;
    meta = (struct mdns_answer_meta *)&payload[i];
    i += sizeof(struct mdns_answer_meta);

    if (rrname != NULL) {
      entry.ttl = ntohl(meta->ttl);
      entry.rrtype = ntohs(meta->rrtype);
      strcpy(entry.rrname, rrname);
      // "A" type resource record
      os_memset(entry.ip, 0, IP_ALEN);
      if (ntohs(meta->rrtype) == 1 && ntohs(meta->rdlength) == IP_ALEN) {
        os_memcpy(entry.ip, &payload[i], IP_ALEN);
      }
      utarray_push_back(answers, &entry);
      os_free(rrname);
    }
    i += ntohs(meta->rdlength);
  }

  *first = i;

  return 0;
}

int decode_mdns_header(uint8_t *packet, struct mdns_header *out) {
  struct mdns_header *mdnsh = (struct mdns_header *)packet;

  out->tid = ntohs(mdnsh->tid);
  out->flags = ntohs(mdnsh->flags);
  out->nqueries = ntohs(mdnsh->nqueries);
  out->nanswers = ntohs(mdnsh->nanswers);
  out->nauth = ntohs(mdnsh->nauth);
  out->nother = ntohs(mdnsh->nother);

  return 0;
}

bool decode_mdns_packet(struct capture_packet *cpac) {
  struct mdns_header mdnsh;
  // size_t payload_len;
  // int pos = 0;
  // char *qname = NULL;
  // size_t first;

  if (cpac->udph != NULL) {
    cpac->mdnsh =
        (struct mdns_header *)((char *)cpac->udph + sizeof(struct udphdr));
  } else
    return false;

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

  // pos = (int)((void*)cpac->mdnsh - (void*)cpac->ethh);
  // if (pos + sizeof(struct dns_header) <= cpac->length) {
  //   payload_len = ((void*) cpac->ethh + cpac->length) - (void*)cpac->mdnsh;
  //   first = sizeof(struct mdns_header);
  //   if (cpac->mdnss.nqueries) {
  //     if (decode_mdns_queries((uint8_t *)cpac->mdnsh, payload_len, &first,
  //     cpac->mdnss.nqueries, &qname) < 0) {
  //       log_trace("decode_mdns_questions fail");
  //       return false;
  //     }
  //     strncpy(cpac->mdnss.qname, qname, MAX_QUESTION_LEN);
  //     os_free(qname);
  //   }
  // }

  // log_trace("mDNS id=%d flags=0x%x nqueries=%d nanswers=%d nauth=%d nother=%d
  // "
  //           "qname=%s",
  //           cpac->mdnss.tid, cpac->mdnss.flags, cpac->mdnss.nqueries,
  //           cpac->mdnss.nanswers, cpac->mdnss.nauth, cpac->mdnss.nother,
  //           cpac->mdnss.qname);

  return true;
}
