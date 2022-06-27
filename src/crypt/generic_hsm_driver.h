/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the definition of generic HSM driver configuration
 * utilities.
 */
#ifndef GENERIC_HSM_DRIVER_H
#define GENERIC_HSM_DRIVER_H

#include <sys/un.h>
#include <sys/types.h>
#include <stdbool.h>
#include <inttypes.h>

struct hsm_context {
  void *hsm_ctx;
};

/**
 * @brief Initialises an HSM context
 *
 * @return struct hsm_context* The returned context, NULL on error
 */
struct hsm_context *init_hsm(void);

/**
 * @brief Closes the HSM context
 *
 * @param context Tje HSM context
 * @return int 0 on success, -1 on failure
 */
int close_hsm(struct hsm_context *context);

/**
 * @brief Generate an HSM key
 *
 * @param context The HSM context
 * @param key The returned key
 * @param key_size The key size
 * @return int 0 on success, -1 on failure
 */
int generate_hsm_key(struct hsm_context *context, uint8_t *key,
                     size_t key_size);

/**
 * @brief Encrypt a byte array wiht the HSM
 *
 * @param context The HSM context
 * @param in The input array
 * @param in_size The input array size
 * @param out The output encrypted array
 * @param out_size The output array size
 * @return int 0 on success, -1 on failure
 */
int encrypt_hsm_blob(struct hsm_context *context, uint8_t *in, size_t in_size,
                     uint8_t **out, size_t *out_size);

/**
 * @brief Decrypt a byte array wiht the HSM
 *
 * @param context The HSM context
 * @param in The input array
 * @param in_size The input array size
 * @param out The output decrypted array
 * @param out_size The output array size
 * @return int 0 on success, -1 on failure
 */
int decrypt_hsm_blob(struct hsm_context *context, uint8_t *in, size_t in_size,
                     uint8_t **out, size_t *out_size);
#endif
