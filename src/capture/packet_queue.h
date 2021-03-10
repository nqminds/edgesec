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
 * @file packet_queue.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the packet queue utilities.
 */

#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include "packet_decoder.h"
#include "../utils/list.h"

/**
 * @brief Packet queueu structure definition
 * 
 */
struct packet_queue {
  void *packet;                 /**< Packet address (mallos allocated) */
  PACKET_TYPES type;            /**< Packet type */
  struct dl_list list;          /**< List defintion */
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
 * @param packet The packet address
 * @param type The packet type
 * @return struct packet_queue* Returned initialised empty packet queue
 */
struct packet_queue* push_packet_queue(struct packet_queue* queue, void *packet, PACKET_TYPES type);

/**
 * @brief Frees the packet queue
 * 
 * @param queue The pointer to the packet queue
 */
void free_packet_queue(struct packet_queue* queue);
#endif
