/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the pcap queue utilities.
 */

#ifndef PCAP_QUEUE_H
#define PCAP_QUEUE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#include <list.h>

#include "../../../utils/attributes.h"

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
 * @param queue The pointer to the pcap queue
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

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang, since
                   // __attribute__((malloc)) accepts no args
/**
 * Declares that the attributed function must be free_pcap_queue()-ed.
 *
 * Expects that this function returns a pointer that must be deallocated with
 * `free_pcap_queue()`.
 *
 * @see __must_free
 */
#define __must_free_pcap_queue                                                 \
  __attribute__((malloc(free_pcap_queue, 1))) __must_check
#else
#define __must_free_pcap_queue __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Initialises an empty pcap queue
 *
 * @return Returned initialised empty pcap queue, or `NULL` on error.
 * You must free this using free_pcap_queue().
 */
__must_free_pcap_queue struct pcap_queue *init_pcap_queue(void);

#endif
