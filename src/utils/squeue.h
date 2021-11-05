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
 * @file squeue.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the string queue utilities.
 */

#ifndef SQUEUE_H
#define SQUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "squeue.h"
#include "list.h"

/**
 * @brief String queue structure definition
 * 
 */
struct string_queue {
  char *str;                    /**< String value */
  ssize_t max_length;           /**< Maximum length of the queue */
  struct dl_list list;          /**< List definition */
};

/**
 * @brief Initialises and empty string queue
 * 
 * @param max_length Maximum queue size, -1 for unlimited
 * @return struct string_queue* Returned initialised empty string queue
 */
struct string_queue* init_string_queue(ssize_t max_length);

/**
 * @brief Pushes a string in the string queue
 * 
 * @param queue The string queue
 * @param str The string value
 * @return 0 on success, -1 on failure
 */
int push_string_queue(struct string_queue* queue, char *str);

/**
 * @brief Extract the first string from the string queueu
 * 
 * @param queue The string queue
 * @param str The returned string
 * @return int 0 on success, -1 on failure
 */
int pop_string_queue(struct string_queue* queue, char **str);

/**
 * @brief Peek the first string from the string queueu
 * 
 * @param queue The string queue
 * @param str The returned string
 * @return int 0 on success, -1 on failure
 */
int peek_string_queue(struct string_queue* queue, char **str);

/**
 * @brief Empty a string entry
 * 
 * @param queue The string queue
 * @param count NUmber of elements to remove, -1 for all
 */
void empty_string_queue(struct string_queue* queue, ssize_t count);

/**
 * @brief Delete a string entry
 * 
 * @param el The string queue entry
 */
void free_string_queue_el(struct string_queue* el);

/**
 * @brief Returns the string queue length
 * 
 * @param el The pointer to the string queue
 * @return ssize_t The string queue length
 */
ssize_t get_string_queue_length(struct string_queue* queue);

/**
 * @brief Frees the string queue
 * 
 * @param queue The pointer to the string queue
 */
void free_string_queue(struct string_queue* queue);

/**
 * @brief Concat teh first count string in the queue
 * 
 * @param queue The pointer to the string queue
 * @param count Number of queue strings to concat, if -1 concat the entire queue
 * @return char* The pointer to the concatenated string, NULL for failure or empty queue
 */
char* concat_string_queue(struct string_queue *queue, ssize_t count);
#endif
