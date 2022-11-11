/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the string queue utilities.
 */

#ifndef SQUEUE_H
#define SQUEUE_H

#include <sys/types.h> // For ssize_t

#include <list.h>

/**
 * @brief String queue structure definition
 *
 */
struct string_queue {
  char *str;           /**< String value */
  ssize_t max_length;  /**< Maximum length of the queue */
  struct dl_list list; /**< List definition */
};

/**
 * @brief Initialises and empty string queue
 *
 * @param max_length Maximum queue size, -1 for unlimited
 * @return struct string_queue* Returned initialised empty string queue
 */
struct string_queue *init_string_queue(ssize_t max_length);

/**
 * @brief Pushes a string in the string queue
 *
 * @param[in, out] queue The string queue
 * @param[in] str The string value
 * @return 0 on success, -1 on failure
 */
int push_string_queue(struct string_queue *queue, const char *str);

/**
 * @brief Extract the first string from the string queueu
 *
 * @param[in, out] queue The string queue
 * @param[out] str The returned string. Please `free()` this
 * variable when done with it.
 * @return int 0 on success, -1 on failure
 */
int pop_string_queue(struct string_queue *queue, char **str);

/**
 * @brief Peek the first string from the string queueu
 *
 * @param[in] queue The string queue
 * @param[out] str The returned string. Please `free()` this
 * variable when done with it.
 * @return int 0 on success, -1 on failure
 */
int peek_string_queue(const struct string_queue *queue, char **str);

/**
 * @brief Empty a string entry
 *
 * @param[in, out] queue The string queue
 * @param count Number of elements to remove, -1 for all
 */
void empty_string_queue(struct string_queue *queue, ssize_t count);

/**
 * @brief Delete a string entry
 *
 * @param[in] el The string queue entry
 */
void free_string_queue_el(struct string_queue *el);

/**
 * @brief Returns the string queue length
 *
 * @param queue The pointer to the string queue
 * @return ssize_t The string queue length
 */
ssize_t get_string_queue_length(const struct string_queue *queue);

/**
 * @brief Frees the string queue
 *
 * @param[in] queue The pointer to the string queue
 */
void free_string_queue(struct string_queue *queue);

/**
 * @brief Concat the first count string in the queue
 *
 * @param[in] queue The pointer to the string queue
 * @param count Number of queue strings to concat, if -1 concat the entire queue
 * @return char* The pointer to the concatenated string, NULL for failure or
 * empty queue
 */
char *concat_string_queue(const struct string_queue *queue, ssize_t count);
#endif
