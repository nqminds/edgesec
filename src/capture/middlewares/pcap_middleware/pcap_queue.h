/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
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

#include "../../../utils/list.h"

/**
 * @brief pcap queueu structure definition
 *
 */
struct pcap_queue {
  struct pcap_pkthdr header; /**< pcap header */
  uint8_t *packet;           /**< pointer to the packet data */
  struct dl_list list;       /**< List definition */
};

/**
 * @brief Initialises and empty pcap queue
 *
 * @return struct pcap_queue* Returned initialised empty pcap queue
 */
struct pcap_queue *init_pcap_queue(void);

/**
 * @brief Pushes a packet in the pcap queue
 *
 * @param queue The pcap queue
 * @param header The pcap header
 * @param packet The pcap packet
 * @return struct pcap_queue* Returned the pcap queue element
 */
struct pcap_queue *push_pcap_queue(struct pcap_queue *queue,
                                   struct pcap_pkthdr *header, uint8_t *packet);

/**
 * @brief Extract the first pcap element from the pcap queueu
 *
 * @param queue The pcap queue
 * @return struct pcap_queue* The returned pcap (NULL if queue is empty)
 */
struct pcap_queue *pop_pcap_queue(struct pcap_queue *queue);

/**
 * @brief Delete a pcap entry
 *
 * @param el The pcap queue entry
 */
void free_pcap_queue_el(struct pcap_queue *el);

/**
 * @brief Returns the pcap queue length
 *
 * @param el The pointer to the pcap queue
 * @return ssize_t The pcap queue length
 */
ssize_t get_pcap_queue_length(struct pcap_queue *queue);

/**
 * @brief Frees the pcap queue
 *
 * @param queue The pointer to the pcap queue
 */
void free_pcap_queue(struct pcap_queue *queue);

/**
 * @brief Checks if pcap queue is empty
 *
 * @param queue The pointer to the packet queue
 * @return 1, is empty, 0 otherwise, -1 for error
 */
int is_pcap_queue_empty(struct pcap_queue *queue);
#endif
