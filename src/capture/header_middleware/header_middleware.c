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
 * @file header_middleware.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the header middleware
 * utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "header_middleware.h"
#include "sqlite_header.h"
#include "packet_decoder.h"
#include "packet_queue.h"

#include "../../utils/allocs.h"
#include "../../utils/os.h"
#include "../../utils/log.h"
#include "../../utils/eloop.h"

#define HEADER_PROCESS_INTERVAL 10 * 1000 // In microseconds

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL,
                                   NULL};
void add_packet_queue(UT_array *tp_array, struct packet_queue *queue) {
  struct tuple_packet *p = NULL;

  while ((p = (struct tuple_packet *)utarray_next(tp_array, p)) != NULL) {
    if (push_packet_queue(queue, *p) == NULL) {
      log_error("push_packet_queue fail");
      // Free the packet if cannot be added to the queue
      free_packet_tuple(p);
    }
  }
}

void eloop_tout_header_handler(void *eloop_ctx, void *user_ctx) {
  (void)eloop_ctx;

  struct middleware_context *context = (struct middleware_context *)user_ctx;
  struct packet_queue *queue, *el;

  if (context == NULL) {
    return;
  }

  if (context->mdata == NULL) {
    return;
  }

  queue = (struct packet_queue *)context->mdata;

  // Process all packets in the queue
  while (is_packet_queue_empty(queue) < 1) {
    if ((el = pop_packet_queue(queue)) != NULL) {
      save_packet_statement(context->db, &(el->tp));

      free_packet_tuple(&el->tp);
      free_packet_queue_el(el);
    }
  }

  if (eloop_register_timeout(context->eloop, 0, HEADER_PROCESS_INTERVAL,
                             eloop_tout_header_handler, NULL,
                             (void *)user_ctx) == -1) {
    log_error("eloop_register_timeout fail");
  }
}

void free_header_middleware(struct middleware_context *context) {
  if (context != NULL) {
    if (context->mdata != NULL) {
      free_packet_queue((struct packet_queue *)context->mdata);
      context->mdata = NULL;
    }
    os_free(context);
  }
}

struct middleware_context *init_header_middleware(sqlite3 *db, char *db_path,
                                                  struct eloop_data *eloop,
                                                  struct pcap_context *pc) {
  (void)db_path;

  struct middleware_context *context = NULL;

  if (db == NULL) {
    log_error("db param is NULL");
    return NULL;
  }

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return NULL;
  }

  if ((context = os_zalloc(sizeof(struct middleware_context))) == NULL) {
    log_errno("zalloc");
    return NULL;
  }

  context->db = db;
  context->eloop = eloop;
  context->pc = pc;

  if ((context->mdata = (void *)init_packet_queue()) == NULL) {
    log_error("init_packet_queue fail");
    free_header_middleware(context);
    return NULL;
  }

  if (init_sqlite_header_db(db) < 0) {
    log_error("init_sqlite_header_db fail");
    free_header_middleware(context);
    return NULL;
  }

  if (eloop_register_timeout(eloop, 0, HEADER_PROCESS_INTERVAL,
                             eloop_tout_header_handler, NULL,
                             (void *)context) == -1) {
    log_error("eloop_register_timeout fail");
    free_header_middleware(context);
    return NULL;
  }

  return context;
}

int process_header_middleware(struct middleware_context *context, char *ltype,
                              struct pcap_pkthdr *header, uint8_t *packet,
                              char *ifname) {
  struct packet_queue *queue;
  int npackets;
  char cap_id[MAX_RANDOM_UUID_LEN];
  UT_array *tp_array = NULL;

  if (context == NULL) {
    log_error("context params is NULL");
    return -1;
  }

  if (context->mdata == NULL) {
    log_error("mdata params is NULL");
    return -1;
  }

  queue = (struct packet_queue *)context->mdata;

  utarray_new(tp_array, &tp_list_icd);

  generate_radom_uuid(cap_id);
  npackets = extract_packets(ltype, header, packet, ifname, cap_id, tp_array);

  if (npackets < 0) {
    log_error("extract_packets fail");
  } else if (npackets > 0) {
    add_packet_queue(tp_array, queue);
  }

  utarray_free(tp_array);

  return 0;
}
