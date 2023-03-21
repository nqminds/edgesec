/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of crypt service configuration
 * utilities.
 */
#ifndef CRYPT_SERVICE_H
#define CRYPT_SERVICE_H

#include <sqlite3.h>
#include <utarray.h>

#include "crypt_config.h"

#include "../utils/allocs.h"
#include "../utils/attributes.h"
#include "../utils/os.h"
#define MAIN_CRYPT_KEY_ID "main"

/**
 * @brief crypt context structure definition
 *
 */
struct crypt_pair {
  const char *key;    /**< The crypt key string. */
  uint8_t *value;     /**< The crypt value array. */
  ssize_t value_size; /**< The crypt value array size. */
};

/**
 * @brief Frees the crypt context
 *
 * @param ctx The crypt context
 */
void free_crypt_service(struct crypt_context *ctx);

#if __GNUC__ >= 11
/**
 * Tells the compiler that return pointer must be deallocated with
 * free_crypt_service()
 * @see @ref __must_free
 */
#define __must_free_crypt_service                                              \
  __attribute__((malloc(free_crypt_service, 1))) __must_check
#else
#define __must_free_crypt_service __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Load the crypt service
 *
 * @param crypt_db_path The crypt db path
 * @param key_id The crypt secrets key id
 * @param[in,out] user_secret The user secret.
 * If creating a new key, the user secret will be loaded from this variable.
 * If loading an existing key, the existing key will be writen to the buffer.
 * @param user_secret_size The user secret size, if zero use the hardware secure
 * element
 * @return The crypt contex, NULL on failure.
 * Use `free_crypt_service()` to deallocate.
 */
__must_free_crypt_service struct crypt_context *
load_crypt_service(const char *crypt_db_path, const char *key_id,
                   uint8_t *user_secret, int user_secret_size);

/**
 * @brief Retrieves a key/value pair from the crypt
 *
 * @param ctx The crypt context
 * @param key The key string
 * @return struct crypt_pair* The returned pair, NULL on failure
 */
struct crypt_pair *get_crypt_pair(struct crypt_context *ctx, const char *key);

/**
 * @brief Inserts a key/value pair into the crypt
 *
 * @param ctx The crypt context
 * @param pair The key/value pair
 * @return 0 on success, -1 on failure
 */
int put_crypt_pair(struct crypt_context *ctx, struct crypt_pair *pair);

/**
 * @brief Frees the crypt pair
 *
 * @param pair The crypt pair
 */
void free_crypt_pair(struct crypt_pair *pair);

#endif
