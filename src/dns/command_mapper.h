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
 * @file command_mapper.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the command mapper.
 */

#ifndef COMMAND_MAPPER_H
#define COMMAND_MAPPER_H

#include <inttypes.h>
#include <stdbool.h>

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"
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
