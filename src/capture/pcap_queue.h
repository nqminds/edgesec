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
#include <stdint.h>

#include "../utils/list.h"

/**
 * @brief pcap queueu structure definition
 * 
 */
struct pcap_queue {
  struct pcap_pkthdr header;            /**< pcap header */
  uint8_t *packet;                      /**< pointer to the packet data */
  struct dl_list list;                  /**< List defintion */
};

/**
 * @brief Initialises and empty pcap queue
 * 
 * @return struct pcap_queue* Returned initialised empty pcap queue
 */
struct pcap_queue* init_pcap_queue(void);

/**
 * @brief Pushes a packet in the pcap queue
 * 
 * @param queue The pcap queue
 * @param header The pcap header
 * @param packet The pcap packet
 * @return struct pcap_queue* Returned the pcap queue element
 */
struct pcap_queue* push_pcap_queue(struct pcap_queue* queue, struct pcap_pkthdr *header, uint8_t *packet);

/**
 * @brief Extract the first pcap element from the pcap queueu
 * 
 * @param queue The pcap queue
 * @return struct pcap_queue* The returned pcap (NULL if queue is empty)
 */
struct pcap_queue* pop_pcap_queue(struct pcap_queue* queue);

/**
 * @brief Delete a pcap entry
 * 
 * @param el The pcap queue entry
 */
void free_pcap_queue_el(struct pcap_queue* el);

/**
 * @brief Returns the pcap queue length
 * 
 * @param el The pointer to the pcap queue
 * @return ssize_t The pcap queue length
 */
ssize_t get_pcap_queue_length(struct pcap_queue* queue);

/**
 * @brief Frees the pcap queue
 * 
 * @param queue The pointer to the pcap queue
 */
void free_pcap_queue(struct pcap_queue* queue);
#endif
