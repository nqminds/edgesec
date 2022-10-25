/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the hash functions.
 */

#include <stddef.h>
#include <stdint.h>

#ifndef HASH_H
#define HASH_H

/**
 * @brief Computes the Merkle–Damgård construction hash for a message
 *
 * @param msg The message pointer
 * @param length The message length
 * @return uint32_t The hash value
 */
uint32_t md_hash(const char *msg, size_t length);

/**
 * @brief Computes the sdbm (a public-domain reimplementation of ndbm)
 * http://www.cse.yorku.ca/~oz/hash.html
 *
 * @param msg The message pointer
 * @param length The message length
 * @return uint32_t The hash value
 */
uint32_t sdbm_hash(const uint8_t *msg, size_t length);
#endif
