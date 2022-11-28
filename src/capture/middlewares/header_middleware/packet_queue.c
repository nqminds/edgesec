/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the packet queue utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/allocs.h"
#include "../../../utils/log.h"
#include "../../../utils/os.h"
#include "packet_decoder.h"
#include "packet_queue.h"

struct packet_queue *init_packet_queue(void) {
  struct packet_queue *queue;
  queue = os_zalloc(sizeof(*queue));

  if (queue == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  dl_list_init(&queue->list);

  return queue;
}

struct packet_queue *push_packet_queue(struct packet_queue *queue,
                                       struct tuple_packet tp) {
  struct packet_queue *el;

  if (queue == NULL) {
    log_debug("queue param is NULL");
    return NULL;
  }

  if ((el = init_packet_queue()) == NULL) {
    log_debug("init_packet_queue fail");
    return NULL;
  }

  el->tp = tp;
  dl_list_add_tail(&queue->list, &el->list);

  return el;
}

struct packet_queue *pop_packet_queue(struct packet_queue *queue) {
  if (queue == NULL)
    return NULL;

  return dl_list_first(&queue->list, struct packet_queue, list);
}

void free_packet_tuple(struct tuple_packet *tp) {
  if (tp != NULL) {
    if (tp->packet != NULL)
      os_free(tp->packet);
  }
}

void free_packet_queue_el(struct packet_queue *el) {
  if (el != NULL) {
    dl_list_del(&el->list);
    os_free(el);
  }
}

void free_packet_queue(struct packet_queue *queue) {
  struct packet_queue *el;

  while ((el = pop_packet_queue(queue)) != NULL)
    free_packet_queue_el(el);

  free_packet_queue_el(queue);
}

ssize_t get_packet_queue_length(struct packet_queue *queue) {
  return (queue != NULL) ? dl_list_len(&queue->list) : 0;
}

int is_packet_queue_empty(struct packet_queue *queue) {
  if (queue == NULL) {
    log_trace("queue param is NULL");
    return -1;
  }

  return dl_list_empty(&queue->list);
}
