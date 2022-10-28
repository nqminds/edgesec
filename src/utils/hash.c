/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the hash functions.
 */
#include <string.h>
#include "hash.h"

static uint32_t md_mix(uint32_t block, uint32_t state) {
  return (state * block) ^ ((state << 3) + (block >> 2));
}

uint32_t md_hash(const char *msg, size_t length) {
  uint32_t state = 0xA5A5A5A5; // IV: A magic number
  uint32_t block = 0;

  // Loop over the message 32-bits at-a-time
  while (length >= 4) {
    memcpy(&block, msg, sizeof(uint32_t));
    state = md_mix(block, state);
    length -= sizeof(uint32_t);
    msg += sizeof(uint32_t);
  }

  // Are there any remaining bytes?
  if (length) {
    memcpy(&block, msg, length);
    state = md_mix(block, state);
  }

  return state;
}

// http://www.cse.yorku.ca/~oz/hash.html
uint32_t sdbm_hash(const uint8_t *msg, size_t length) {
  size_t idx;
  uint32_t hash = 0;
  for (idx = 0, idx = 0; idx < length; idx++) {
    hash = msg[idx] + (hash << 6) + (hash << 16) - hash;
  }

  return hash;
}
