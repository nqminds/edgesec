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
#include "crypt_service.h"

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/cryptou.h"
#include "../utils/base64.h"

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

struct secrets_row* prepare_secret_entry(char *key_id, uint8_t *key, int key_size, uint8_t *salt, int salt_size, uint8_t *iv, int iv_size)
{
  size_t out_len;
  struct secrets_row *row = os_malloc(sizeof(struct secrets_row));

  row->id = os_strdup(key_id);
  row->value = base64_encode(key, key_size, &out_len);
  row->salt = base64_encode(salt, salt_size, &out_len);
  row->iv = base64_encode(iv, iv_size, &out_len);

  return row;
}

int extract_secret_entry(struct secrets_row* row, uint8_t *key, int *key_size,
                         uint8_t *salt, int *salt_size, uint8_t *iv, int *iv_size)
{
  size_t out_len;
  char *buf;
  
  if (row->value == NULL) {
    *key_size = 0;
  } else {
    buf = base64_decode(row->value, strlen(row->value), &out_len);
    if (buf == NULL) {
      log_trace("base64_decode fail");
      return -1;
    }
    *key_size = out_len;
    os_memcpy(key, buf, *key_size);
    os_free(buf);
  }

  if (row->salt == NULL) {
    *salt_size = 0;
  } else {
    buf = base64_decode(row->salt, strlen(row->salt), &out_len);
    if (buf == NULL) {
      log_trace("base64_decode fail");
      return -1;
    }
    *salt_size = out_len;
    os_memcpy(salt, buf, *salt_size);
    os_free(buf);
  }

  if (row->iv == NULL) {
    *iv_size = 0;
  } else {
    buf = base64_decode(row->iv, strlen(row->iv), &out_len);
    if (buf == NULL) {
      log_trace("base64_decode fail");
      return -1;
    }
    *iv_size = out_len;
    os_memcpy(iv, buf, *iv_size);
    os_free(buf);
  }

  return 0;
}

int extract_user_crypto_key_entry(struct secrets_row *row_secret, uint8_t *user_secret, int user_secret_size,
                            uint8_t *crypto_key)
{
  uint8_t user_key[AES_KEY_SIZE];
  uint8_t user_key_salt[SALT_SIZE];
  uint8_t enc_crypto_key[AES_KEY_SIZE + AES_BLOCK_SIZE];
  uint8_t iv[IV_SIZE];
  int enc_crypto_key_size;
  int salt_size;
  int iv_size;
  int crypto_key_size = 0;

  if (extract_secret_entry(row_secret, enc_crypto_key, &enc_crypto_key_size,
                       user_key_salt, &salt_size, iv, &iv_size) < 0)
  {
    log_trace("extract_secret_entry fail");
    return -1;
  }

  if (salt_size != SALT_SIZE) {
    log_trace("Wrong salt size=%d", salt_size);
    return -1;
  }

  if (iv_size != IV_SIZE) {
    log_trace("Wrong iv size=%d", iv_size);
    return -1;
  }

  // Generate the enc/dec key using the user supplied key
  if (generate_user_key(user_secret, user_secret_size, user_key,
                        AES_KEY_SIZE, user_key_salt, SALT_SIZE) < 0)
  {
    log_trace("generate_user_key fail");
    return -1;
  }

  if ((crypto_key_size = crypto_decrypt(enc_crypto_key, enc_crypto_key_size, user_key, iv, crypto_key)) < 0) {
    log_trace("crypto_decrypt fail");
    return -1;
  }

  return crypto_key_size;
}

struct secrets_row * generate_user_crypto_key_entry(char *key_id, uint8_t *user_secret, int user_secret_size,
                                                    uint8_t *crypto_key)
{
  uint8_t user_key[AES_KEY_SIZE];
  uint8_t user_key_salt[SALT_SIZE];
  uint8_t iv[IV_SIZE];
  uint8_t enc_crypto_key[AES_KEY_SIZE + AES_BLOCK_SIZE];

  int enc_crypto_key_size;
  if (!crypto_gensalt(user_key_salt, SALT_SIZE)) {
    log_trace("crypto_gensalt fail");
    return NULL;        
  }

  // Generate the enc/dec key using the user supplied key
  if (generate_user_key(user_secret, user_secret_size, user_key,
                        AES_KEY_SIZE, user_key_salt, SALT_SIZE) < 0)
  {
    log_trace("generate_user_key fail");
    return NULL;
  }

  if (!crypto_geniv(iv, IV_SIZE)) {
    log_trace("crypto_geniv fail");
    return NULL;
  }

  if ((enc_crypto_key_size = crypto_encrypt(crypto_key, AES_KEY_SIZE, user_key, iv, enc_crypto_key)) < 0) {
    log_trace("crypto_encrypt fail");
    return NULL;
  }

  return prepare_secret_entry(key_id, enc_crypto_key, enc_crypto_key_size, user_key_salt, SALT_SIZE, iv, IV_SIZE);
}

struct crypt_context* load_crypt_service(char *crypt_db_path, char *key_id,
                                         uint8_t *user_secret, int user_secret_size)
{
  sqlite3 *db = NULL;
  struct crypt_context *context;
  struct secrets_row *row_secret;

  if (key_id == NULL) {
    log_trace("key_id param is NULL");
    return NULL;
  }

  if (open_sqlite_crypt_db(crypt_db_path, &db) < 0) {
    log_trace("open_sqlite_crypt_db fail");
    free_crypt_service(context);

    return NULL;
  }

  context = (struct crypt_context*) os_zalloc(sizeof(struct crypt_context));
  if (context == NULL) {
    log_err("os_zalloc");
    free_sqlite_crypt_db(db);
    return NULL;
  }

  context->crypt_db = db;
  strncpy(context->key_id, key_id, MAX_KEY_ID_SIZE);

  // Retrieve an existing key
  if ((row_secret = get_sqlite_secrets_row(context->crypt_db, key_id)) == NULL) {
    log_trace("get_sqlite_secrets_row fail");
    free_crypt_service(context);
    return NULL;
  }

  if (row_secret->id == NULL) {
    free_sqlite_secrets_row(row_secret);

    log_trace("No secret with key=%s, generating new one", key_id);
    // Create encryption key
    if (!crypto_genkey(context->crypto_key, AES_KEY_SIZE)) {
      log_trace("crypto_genkey fail");
      free_crypt_service(context);
      free_sqlite_secrets_row(row_secret);
      return NULL;
    }

    if (user_secret_size) {
      log_debug("Using user supplied secret");
      
      if ((row_secret = generate_user_crypto_key_entry(key_id, user_secret, user_secret_size,
                                                    context->crypto_key)) == NULL)
      {
        log_trace("generate_user_crypto_key_entry fail");
        free_crypt_service(context);
        free_sqlite_secrets_row(row_secret);
        return NULL;
      }

      if (save_sqlite_secrets_entry(context->crypt_db, row_secret) < 0) {
        log_trace("save_sqlite_secrets_entry fail");
        free_sqlite_secrets_row(row_secret);
        free_crypt_service(context);
        return NULL;
      }
      free_sqlite_secrets_row(row_secret);
    } else {
      log_debug("Using hardware secure element");
      log_trace("Not implemented, yet");
      free_crypt_service(context);
      return NULL;      
    }
  } else {
    log_trace("found crypto key=%s", row_secret->id);
    if (user_secret_size > 0) {
      if (extract_user_crypto_key_entry(row_secret, user_secret, user_secret_size,
                                  context->crypto_key) < 0)
      {
        log_trace("extract_user_crypto_key fail");
        free_sqlite_secrets_row(row_secret);
        free_crypt_service(context);
        return NULL;
      }
      free_sqlite_secrets_row(row_secret);
    } else {
      log_debug("Using hardware secure element");
      log_trace("Not implemented, yet");
      free_sqlite_secrets_row(row_secret);
      free_crypt_service(context);
      return NULL;      
    }
  }
  
  return context;
}

void free_crypt_pair(struct crypt_pair *pair)
{
  if (pair != NULL) {
    if (pair->value != NULL)
      os_free(pair->value);

    os_free(pair);
  }
}

struct crypt_pair* get_crypt_pair(struct crypt_context *ctx, char *key)
{
  struct crypt_pair *pair;
  struct store_row *row;
  uint8_t *enc_value;
  uint8_t *iv;
  size_t iv_size, value_size;

  if (key == NULL) {
    log_trace("key param is NULL");
    return NULL;
  }

  if (!strlen(key)) {
    log_trace("key param is empty");
    return NULL;
  }

  pair = (struct crypt_pair *) os_malloc(sizeof(struct crypt_pair));
  if (pair == NULL) {
    log_err("os_malloc");
    return NULL;
  }

  pair->key = key;

  if ((row = get_sqlite_store_row(ctx->crypt_db, key)) == NULL) {
    log_trace("get_sqlite_store_row fail");
    free_crypt_pair(pair);
    return NULL;
  }

  if (row->key == NULL) {
    pair->value = NULL;
    pair->value_size = 0;
    free_sqlite_store_row(row);
    return pair;
  }

  if (row->value != NULL) {
    iv = base64_decode(row->iv, strlen(row->iv), &iv_size);
    enc_value = base64_decode(row->value, strlen(row->value), &value_size);

    pair->value = os_malloc(value_size);
    if (pair->value == NULL) {
      log_err("os_malloc");
      os_free(iv);
      os_free(enc_value);
      free_crypt_pair(pair);
      free_sqlite_store_row(row);
      return NULL;
    }

    if ((pair->value_size = crypto_decrypt(enc_value, value_size, ctx->crypto_key,
                                         iv, pair->value)) < 0) {
      log_trace("crypto_decrypt fail");
      os_free(iv);
      os_free(enc_value);
      free_crypt_pair(pair);
      free_sqlite_store_row(row);
      return NULL;
    }

    os_free(iv);
    os_free(enc_value);
  } else {
    pair->value = NULL;
    pair->value_size = 0;
  }

  free_sqlite_store_row(row);
  return pair;
}

int put_crypt_pair(struct crypt_context *ctx, struct crypt_pair *pair)
{
  struct store_row row;
  uint8_t *enc_value;
  uint8_t iv[IV_SIZE];
  int enc_value_size;
  size_t out_len;

  if (pair == NULL) {
    log_trace("pair param is NULL");
    return -1;
  }

  if (pair->key == NULL) {
    log_trace("pair key is NULL");
    return -1;
  }

  if (!strlen(pair->key)) {
    log_trace("pair key is empty");
    return -1;
  }

  if (pair->value_size && pair->value != NULL) {
    if (!crypto_geniv(iv, IV_SIZE)) {
      log_trace("crypto_geniv fail");
      return -1;
    }

    enc_value = os_malloc(pair->value_size + AES_BLOCK_SIZE);

    if (enc_value == NULL) {
      log_err("os_malloc");
      return -1;
    }

    if ((enc_value_size = crypto_encrypt(pair->value, pair->value_size, ctx->crypto_key,
                                         iv, enc_value)) < 0) {
      log_trace("crypto_encrypt fail");
      os_free(enc_value);
      return -1;
    }

    row.value = base64_encode(enc_value, enc_value_size, &out_len);
    row.iv = base64_encode(iv, IV_SIZE, &out_len);

    os_free(enc_value);
  } else {
    row.value = NULL;
    row.iv = NULL;
  }

  row.key = pair->key;
  row.id = ctx->key_id;

  if (save_sqlite_store_entry(ctx->crypt_db, &row) < 0) {
    log_trace("save_sqlite_store_entry fail");
    if (row.value != NULL) os_free(row.value);
    if (row.iv != NULL) os_free(row.iv);
    return -1;
  }

  if (row.value != NULL) os_free(row.value);
  if (row.iv != NULL) os_free(row.iv);
  return 0;
}
