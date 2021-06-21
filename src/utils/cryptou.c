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
 * @file cryptou.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the cryptographic utilities.
 */

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "cryptou.h"

#include "../utils/log.h"
#include "../utils/base64.h"

int crypto_geniv(uint8_t *buf, int iv_size)
{
  return RAND_bytes(buf, iv_size);
}

int crypto_gensalt(uint8_t *buf, int salt_size)
{
  return RAND_bytes(buf, salt_size);
}

int crypto_genkey(uint8_t *buf, int key_size)
{
  return RAND_bytes(buf, key_size);
}

int crypto_buf2key(uint8_t *buf, int buf_size, uint8_t *salt, int salt_size,
                   uint8_t *key, int key_size)
{
  if (PKCS5_PBKDF2_HMAC(buf, buf_size, salt, salt_size, MAX_KEY_ITERATIONS,
                    EVP_sha256(), key_size, key) < 1) {
    log_trace("PKCS5_PBKDF2_HMAC fail wit code=%d", ERR_get_error());
    return -1;
  }

  return 0;
}

int crypto_encrypt(uint8_t *in, int in_size, uint8_t *key,
                   uint8_t *iv, uint8_t *out)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    log_trace("EVP_CIPHER_CTX_new fail with code=%d", ERR_get_error());
    return -1;
  }

  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    log_trace("EVP_EncryptInit_ex fail with code=%d", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, out, &len, in, in_size)) {
    log_trace("EVP_EncryptUpdate fail with code=%d", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  ciphertext_len = len;

  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
    log_trace("EVP_EncryptFinal_ex fail with code=%d", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int crypto_decrypt(uint8_t *in, int in_size, uint8_t *key,
                   uint8_t *iv, uint8_t *out)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    log_trace("EVP_CIPHER_CTX_new fail with code=%d", ERR_get_error());
    return -1;
  }

  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    log_trace("EVP_DecryptInit_ex fail with code=%d", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if(1 != EVP_DecryptUpdate(ctx, out, &len, in, in_size)) {
    log_trace("EVP_DecryptUpdate fail with code=%d", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  plaintext_len = len;

  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) {
    log_trace("EVP_DecryptFinal_ex fail with code=%d", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}