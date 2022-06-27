/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
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
