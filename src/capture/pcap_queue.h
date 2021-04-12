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
 * @file pcap_queue.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the pcap queue utilities.
 */

#ifndef PCAP_QUEUE_H
#define PCAP_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "../utils/list.h"

/**
 * @brief pcap queueu structure definition
 * 
 */
struct pcap_queue {
  struct pcap_pkthdr header;        /**< pcap header */
  struct dl_list list;              /**< List defintion */
};

/**
 * @brief Initialises and empty packet queue
 * 
 * @return struct packet_queue* Returned initialised empty packet queue
 */
struct packet_queue* init_packet_queue(void);

/**
 * @brief Pushes a packet in the packet queue
 * 
 * @param queue The packet queue
 * @param tp The packet tuple
 * @return struct packet_queue* Returned the packet queue element
 */
struct packet_queue* push_packet_queue(struct packet_queue* queue, struct tuple_packet tp);

/**
 * @brief Extract the first packet from the packet queueu
 * 
 * @param queue The packet queue
 * @return struct packet_queue* The returned packet (NULL if queue is empty)
 */
struct packet_queue* pop_packet_queue(struct packet_queue* queue);

/**
 * @brief Delete a packet entry
 * 
 * @param el The packet queue entry
 */
void free_packet_queue_el(struct packet_queue* el);

/**
 * @brief Returns the packet queue length
 * 
 * @param el The pointer to the packet queue
 * @return ssize_t The packet queue length
 */
ssize_t get_packet_queue_length(struct packet_queue* queue);

/**
 * @brief Frees the packet queue
 * 
 * @param queue The pointer to the packet queue
 */
void free_packet_queue(struct packet_queue* queue);
#endif
