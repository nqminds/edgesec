/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the hashmap utilities.
 */

#ifndef HASHMAP_H_
#define HASHMAP_H_

#include <stdbool.h>

#include "uthash.h"

#define HASH_KEY_CHAR_SIZE 20

/**
 * @brief keyd array hasmap structure definition
 *
 */
typedef struct hashmap_str_keychar {
  char key[HASH_KEY_CHAR_SIZE]; /**< key (string is WITHIN the structure) */
  char *value;                  /**< value of the hashmap */
  UT_hash_handle hh;            /**< makes this structure hashable */
} hmap_str_keychar;

/**
 * @brief string hasmap structure definition
 *
 */
typedef struct hashmap_str_keyptr {
  char *key;         /**< key (string is WITHIN the structure) */
  char *value;       /**< value of the hashmap */
  UT_hash_handle hh; /**< makes this structure hashable */
} hmap_str_keyptr;

/**
 * @brief Retrieves a string from string hashmap for a given key
 *
 * @param hmap The string hashmap object
 * @param keyptr The hashmap key
 * @return char* Returned string, NULL if not found
 */
char *hmap_str_keychar_get(hmap_str_keychar **hmap, char *keyptr);

/**
 * @brief Inserts a string into a string hashmap for a given key
 *
 * @param hmap The string hashmap object
 * @param keyptr The hashmap key
 * @param value The hashmap string value
 * @return true on succes, false if there's an insertion error
 */
bool hmap_str_keychar_put(hmap_str_keychar **hmap, char *keyptr, char *value);

/**
 * @brief Deletes the string hashmap object
 *
 * @param hmap The string hashmap object
 */
void hmap_str_keychar_free(hmap_str_keychar **hmap);

#endif
