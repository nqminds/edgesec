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
 * @file command_mapper.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the command mapper.
 */

#include <inttypes.h>
#include <stdbool.h>

#include "command_mapper.h"
#include "../utils/hash.h"

void free_command_mapper(hmap_command_conn **hmap)
{
  hmap_command_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current);
    os_free(current);
  }
}

int put_command_mapper(hmap_command_conn **hmap, char *command)
{
  hmap_command_conn *s;
  uint32_t hash_key;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return -1;
  }

  if (command == NULL) {
    log_trace("command param is NULL");
    return -1;
  }

  hash_key = md_hash(command, strlen(command));

  HASH_FIND(hh, *hmap, &hash_key, sizeof(uint32_t), s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_command_conn *) os_malloc(sizeof(hmap_command_conn));
	if (s == NULL) {
	  log_errno("os_malloc");
      return -1;
	}

	// Copy the key and value
    s->key = hash_key;
	s->value = true; //TBD

    HASH_ADD(hh, *hmap, key, sizeof(uint32_t), s);
  }

  return 0;
}

int check_command_mapper(hmap_command_conn **hmap, char *command)
{
  hmap_command_conn *s = NULL;
  uint32_t hash_key;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return -1;
  }

  if (command == NULL) {
    log_trace("command param is NULL");
    return -1;
  }

  hash_key = md_hash(command, strlen(command));

  HASH_FIND(hh, *hmap, &hash_key, sizeof(uint32_t), s);

  return (s != NULL);
}
