/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the command mapper.
 */

#ifndef COMMAND_MAPPER_H
#define COMMAND_MAPPER_H

#include <inttypes.h>
#include <stdbool.h>
#include <utarray.h>
#include <uthash.h>

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/hashmap.h"

/**
 * @brief Command mapper connection structure
 *
 */
typedef struct hashmap_command_conn { /**< hashmap key */
  uint32_t key;
  int value;         /**< Command info TBD */
  UT_hash_handle hh; /**< hashmap handle */
} hmap_command_conn;

/**
 * @brief Frees the command mapper connection object
 *
 * @param hmap Command mapper connection object
 */
void free_command_mapper(hmap_command_conn **hmap);

/**
 * @brief Insert a command into the command mapper connection object
 *
 * @param hmap Command mapper object
 * @param command The command string
 * @return 0 on success, -1 on failure
 */
int put_command_mapper(hmap_command_conn **hmap, char *command);

/**
 * @brief Check if a command is in the command mapper connection object
 *
 * @param hmap Command mapper object
 * @param command The command string
 * @return 1 if command is in hmap, 0 otherwise, -1 on failure
 */
int check_command_mapper(hmap_command_conn **hmap, char *command);
#endif
