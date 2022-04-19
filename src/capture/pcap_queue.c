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
 * @file pcap_queue.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the pcap queue utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "pcap_queue.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"

struct pcap_queue *init_pcap_queue(void) {
  struct pcap_queue *queue;
  queue = os_zalloc(sizeof(*queue));

  if (queue == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  dl_list_init(&queue->list);

  return queue;
}

struct pcap_queue *push_pcap_queue(struct pcap_queue *queue,
                                   struct pcap_pkthdr *header,
                                   uint8_t *packet) {
  struct pcap_queue *el;

  if (queue == NULL) {
    log_debug("queue param is NULL");
    return NULL;
  }

  if (header == NULL) {
    log_debug("header param is NULL");
    return NULL;
  }

  if (packet == NULL) {
    log_debug("packet param is NULL");
    return NULL;
  }

  if ((el = init_pcap_queue()) == NULL) {
    log_debug("init_packet_queue fail");
    return NULL;
  }

  os_memcpy(&el->header, header, sizeof(struct pcap_pkthdr));
  el->packet = os_malloc(header->caplen);
  if (el->packet == NULL) {
    log_errno("os_malloc");
    return NULL;
  }

  os_memcpy(el->packet, packet, header->caplen);

  dl_list_add_tail(&queue->list, &el->list);

  return el;
}

struct pcap_queue *pop_pcap_queue(struct pcap_queue *queue) {
  if (queue == NULL)
    return NULL;

  return dl_list_first(&queue->list, struct pcap_queue, list);
}

void free_pcap_queue_el(struct pcap_queue *el) {
  if (el != NULL) {
    dl_list_del(&el->list);
    os_free(el->packet);
    os_free(el);
  }
}

void free_pcap_queue(struct pcap_queue *queue) {
  struct pcap_queue *el;

  while ((el = pop_pcap_queue(queue)) != NULL)
    free_pcap_queue_el(el);

  free_pcap_queue_el(queue);
}

ssize_t get_pcap_queue_length(struct pcap_queue *queue) {
  return (queue != NULL) ? dl_list_len(&queue->list) : 0;
}

int is_pcap_queue_empty(struct pcap_queue *queue) {
  if (queue == NULL) {
    log_trace("queue param is NULL");
    return -1;
  }

  return dl_list_empty(&queue->list);
}
