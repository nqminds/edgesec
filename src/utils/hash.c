/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the hash functions.
 */
#include <stddef.h>
#include <stdint.h>

#include "hash.h"
#include "allocs.h"

static uint32_t md_mix(uint32_t block, uint32_t state) {
  return (state * block) ^ ((state << 3) + (block >> 2));
}

uint32_t md_hash(const char *msg, size_t length) {
  uint32_t state = 0xA5A5A5A5; // IV: A magic number
  uint32_t block = 0;

  // Loop over the message 32-bits at-a-time
  while (length >= 4) {
    os_memcpy(&block, msg, sizeof(uint32_t));
    state = md_mix(block, state);
    length -= sizeof(uint32_t);
    msg += sizeof(uint32_t);
  }

  // Are there any remaining bytes?
  if (length) {
    os_memcpy(&block, msg, length);
    state = md_mix(block, state);
  }

  return state;
}
