/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the header middleware
 * utilities.
 */
#include "header_middleware.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sqlite3.h>
#include <string.h>

#include <eloop.h>
#include "../../../utils/allocs.h"
#include "../../../utils/log.h"
#include "../../../utils/os.h"
#include "packet_decoder.h"
#include "packet_queue.h"
#include "sqlite_header.h"

#include "../../pcap_service.h"

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

  if (edge_eloop_register_timeout(context->eloop, 0, HEADER_PROCESS_INTERVAL,
                                  eloop_tout_header_handler, NULL,
                                  (void *)user_ctx) == -1) {
    log_error("edge_eloop_register_timeout fail");
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
                                                  struct pcap_context *pc,
                                                  char *params) {
  (void)db_path;

  struct middleware_context *context = NULL;

  log_info("Init header middleware...");

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
  context->params = params;

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

  if (edge_eloop_register_timeout(eloop, 0, HEADER_PROCESS_INTERVAL,
                                  eloop_tout_header_handler, NULL,
                                  (void *)context) == -1) {
    log_error("edge_eloop_register_timeout fail");
    free_header_middleware(context);
    return NULL;
  }

  return context;
}

int process_header_middleware(struct middleware_context *context,
                              const char *ltype, struct pcap_pkthdr *header,
                              uint8_t *packet, char *ifname) {
  struct packet_queue *queue;
  int npackets;
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

  npackets = extract_packets(ltype, header, packet, ifname, tp_array);

  if (npackets < 0) {
    log_error("extract_packets fail");
  } else if (npackets > 0) {
    add_packet_queue(tp_array, queue);
  }

  utarray_free(tp_array);

  return 0;
}
struct capture_middleware header_middleware = {
    .init = init_header_middleware,
    .process = process_header_middleware,
    .free = free_header_middleware,
    .name = "header middleware",
};
