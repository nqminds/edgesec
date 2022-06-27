/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of crypt configuration structure.
 */
#ifndef CRYPT_CONFIG_H
#define CRYPT_CONFIG_H

#include <sqlite3.h>

#include "generic_hsm_driver.h"

#include "../utils/cryptou.h"

#define MAX_KEY_ID_SIZE 255

/**
 * @brief crypt context structure definition
 *
 */
struct crypt_context {
  struct hsm_context *hcontext; /**< The HSM context. */
  sqlite3 *crypt_db;            /**< The crypt sqlite db structure. */
  char key_id[MAX_KEY_ID_SIZE]; /**< The crypt secrets key id. */
  uint8_t crypto_key[AES_KEY_SIZE +
                     AES_BLOCK_SIZE]; /**< The crypt master key array (Need to
                                         be store securely or retrived from the
                                         secure memory). */
};

#endif
