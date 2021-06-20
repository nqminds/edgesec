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

struct crypt_context* load_crypt_service(char *crypt_db_path, char *key_id,
                                         uint8_t *user_key, int user_key_size)
{
  struct crypt_context *context;
  struct secrets_row *row_secret;
  uint8_t master_key[AES_KEY_SIZE];
  uint8_t test[1000];
  uint8_t salt[SALT_SIZE];

  if (key_id == NULL) {
    log_trace("key_id param is NULL");
    return NULL;
  }

  // User the hardware secure memory
  if (!user_key_size) {
    log_trace("User key is empty, using hardware secure memory.");
  } else {
    log_trace("Using user secret key, generating AES key.");
    if (crypto_buf2key(user_key, user_key_size, salt, SALT_SIZE, AES_KEY_SIZE, master_key) < 0) {
      log_trace("crypto_buf2key fail");
      return NULL;
    }
    printf_hex(test, 1000, master_key, AES_KEY_SIZE, 1);
    log_trace("%s", test);
  }

  context = (struct crypt_context*) os_malloc(sizeof(struct crypt_context));

  if (open_sqlite_crypt_db(crypt_db_path, &context->crypt_db) < 0) {
    log_trace("open_sqlite_crypt_db fail");
    free_crypt_service(context);

    return NULL;
  }

  if ((row_secret = get_sqlite_secrets_row(context->crypt_db, key_id)) == NULL) {
    // Create secret 
  }

  return context;
}
