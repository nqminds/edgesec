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
 * @file hash.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the hash functions.
 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

uint32_t md_mix(uint32_t block, uint32_t state)
{
  return (state * block) ^ ((state << 3) + (block >> 2));
}

uint32_t md_hash(const char* msg, size_t length)
{
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
