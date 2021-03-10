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
 * @file packet_queue.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the packet queue utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_queue.h"
#include "../utils/os.h"
#include "../utils/log.h"

struct packet_queue* init_packet_queue(void)
{
  struct packet_queue *queue;
  queue = os_zalloc(sizeof(*queue));

  if (queue == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

  dl_list_init(&queue->list);

  return queue;
}

struct packet_queue* push_packet_queue(struct packet_queue* queue, void *packet, PACKET_TYPES type)
{
  struct packet_queue* el;

  if (queue == NULL) {
    log_trace("queue param is NULL");
    return NULL;
  }
  
  if ((el = init_packet_queue()) == NULL) {
    log_trace("init_packet_queue fail");
    return NULL;
  }

  el->packet = packet;
  el->type = type;
  dl_list_add_tail(&queue->list, &el->list);
}

struct packet_queue* pop_packet_queue(struct packet_queue* queue)
{
  if (queue == NULL)
    return NULL;

  return dl_list_first(&queue->list, struct packet_queue, list);
}

void free_packet_queue_el(struct packet_queue* el)
{
  if (el) {
    dl_list_del(&el->list);
    if (el->packet != NULL)
      os_free(el->packet);
	os_free(el);
  }
}

void free_packet_queue(struct packet_queue* queue)
{
  struct packet_queue* el;

  while ((el = pop_packet_queue(queue)) != NULL)
    free_packet_queue_el(el);

  free_packet_queue_el(queue);
}
