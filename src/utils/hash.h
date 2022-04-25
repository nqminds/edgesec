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
 * @file hash.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the hash functions.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#ifndef HASH_H
#define HASH_H

#define SHA256_HASH_LEN 32

/**
 * @brief Computes the Merkle–Damgård construction hash for a message
 *
 * @param msg The message pointer
 * @param length The message length
 * @return uint32_t The hash value
 */
uint32_t md_hash(const char *msg, size_t length);

/**
 * @brief Computes the sha256 for an array
 *
 * @param hash The resulting 32 byte hash
 * @param input The input array
 * @param len The size of the array
 */
void sha256_hash(uint8_t hash[SHA256_HASH_LEN], const void *input, size_t len);
#endif
