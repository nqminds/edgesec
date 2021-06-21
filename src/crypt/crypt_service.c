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
 * @file crypt_service.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of crypt service configuration utilities.
 */

#include "sqlite_crypt_writer.h"
#include "crypt_config.h"

#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/cryptou.h"

void free_crypt_service(struct crypt_context *ctx)
{
  if (ctx != NULL) {
    free_sqlite_crypt_db(ctx->crypt_db);
    os_free(ctx);
  }
}

int generate_user_key(uint8_t *user_secret, int user_secret_size,
                      uint8_t *user_key, int user_key_size,
                      uint8_t *user_key_salt, int user_key_salt_size)
{
  if (crypto_buf2key(user_secret, user_secret_size, user_key_salt, user_key_salt_size, user_key, user_key_size) < 0) {
    log_trace("crypto_buf2key fail");
    return -1;
  }

  return 0;
}

int encrypt_master_key(uint8_t *key, int key_size, uint8_t *user_key, int user_key_size,
                       uint8_t *out, int out_size)
{
  if (!user_key_size) {
    // Use secure element key
    log_trace("Secure element not implemented");
    return -1;
  } else {
    // Use user key
  }


}

struct crypt_context* load_crypt_service(char *crypt_db_path, char *key_id,
                                         uint8_t *user_secret, int user_secret_size)
{
  struct crypt_context *context;
  struct secrets_row *row_secret;
  uint8_t user_key[AES_KEY_SIZE];
  uint8_t user_key_salt[SALT_SIZE];
  uint8_t crypto_key[AES_KEY_SIZE];
  uint8_t enc_crypto_key[AES_KEY_SIZE + AES_BLOCK_SIZE];
  uint8_t iv[IV_SIZE];
  int enc_crypto_key_size;

  uint8_t test[1000];

  if (key_id == NULL) {
    log_trace("key_id param is NULL");
    return NULL;
  }

  context = (struct crypt_context*) os_malloc(sizeof(struct crypt_context));

  if (open_sqlite_crypt_db(crypt_db_path, &context->crypt_db) < 0) {
    log_trace("open_sqlite_crypt_db fail");
    free_crypt_service(context);

    return NULL;
  }

  // Retrieve an existing key
  row_secret = get_sqlite_secrets_row(context->crypt_db, key_id);
  if (row_secret  == NULL) {
    log_trace("No secret with key=%s found, generating new one", key_id);
    // Create encryption key
    if (!crypto_genkey(crypto_key, AES_KEY_SIZE)) {
      log_trace("crypto_genkey fail");
      free_crypt_service(context);
      return NULL;
    }

    if (user_secret_size) {
      log_debug("Using user supplied secret");
      if (!crypto_gensalt(user_key_salt, SALT_SIZE)) {
        log_trace("crypto_gensalt fail");
        free_crypt_service(context);
        return NULL;        
      }

      // Generate the enc/dec key using the user supplied key
      if (generate_user_key(user_secret, user_secret_size, user_key,
                            AES_KEY_SIZE, user_key_salt, SALT_SIZE) < 0)
      {
        log_trace("generate_user_key fail");
        free_crypt_service(context);
        return NULL;
      }

      if (!crypto_geniv(iv, IV_SIZE)) {
        log_trace("crypto_geniv fail");
        free_crypt_service(context);
        return NULL;
      }

      if ((enc_crypto_key_size =crypto_encrypt(crypto_key, AES_KEY_SIZE, user_key, iv, enc_crypto_key)) < 0) {
        log_trace("crypto_encrypt fail");
        free_crypt_service(context);
        return NULL;
      }

      printf_hex(test, 1000, user_key, AES_KEY_SIZE, 1);
      log_trace("%s", test);
    } else {
      log_debug("Using hardware secure element");
      log_trace("Not implemented, yet");
      free_crypt_service(context);
      return NULL;      
    }
  } else {
    log_trace("key=%s found", key_id);
  }

  // User the hardware secure memory
  // if (!user_key_size) {
  //   log_trace("User key is empty, using hardware secure memory.");
  // } else {
  //   log_trace("Using user secret key, generating AES key.");


  //   if (crypto_buf2key(user_key, user_key_size, salt, SALT_SIZE, AES_KEY_SIZE, master_key) < 0) {
  //     log_trace("crypto_buf2key fail");
  //     free_crypt_service(context);
  //     return NULL;
  //   }
  //   printf_hex(test, 1000, master_key, AES_KEY_SIZE, 1);
  //   log_trace("%s", test);
  // }

  return context;
}
