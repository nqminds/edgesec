/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @brief File containing the implementation of the command mapper.
 */

#include <inttypes.h>
#include <stdbool.h>

#include "command_mapper.h"
#include "../utils/hash.h"

void free_command_mapper(hmap_command_conn **hmap) {
  hmap_command_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current);
    os_free(current);
  }
}

int put_command_mapper(hmap_command_conn **hmap, char *command) {
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

  HASH_FIND(hh, *hmap, &hash_key, sizeof(uint32_t),
            s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_command_conn *)os_malloc(sizeof(hmap_command_conn));
    if (s == NULL) {
      log_errno("os_malloc");
      return -1;
    }

    // Copy the key and value
    s->key = hash_key;
    s->value = true; // TBD

    HASH_ADD(hh, *hmap, key, sizeof(uint32_t), s);
  }

  return 0;
}

int check_command_mapper(hmap_command_conn **hmap, char *command) {
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
