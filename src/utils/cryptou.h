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
 * @file cryptou.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the cryptographic utilities.
 */

#ifndef CRYPTOU_H
#define CRYPTOU_H

#include <stdint.h>

#define AES_BLOCK_SIZE      16
#define IV_SIZE             AES_BLOCK_SIZE
#define SALT_SIZE           16
#define AES_KEY_SIZE        32
#define MAX_KEY_ITERATIONS  1000

#define MAX_CERT_FIELD_SIZE  64

#ifdef __cplusplus
extern "C" {
#endif

struct certificate_meta {
  long not_before;
  long not_after;
  char c[MAX_CERT_FIELD_SIZE];
  char o[MAX_CERT_FIELD_SIZE];
  char ou[MAX_CERT_FIELD_SIZE];
  char cn[MAX_CERT_FIELD_SIZE]; 
};

/**
 * @brief Generate IV
 * 
 * @param The output buffer
 * @param The IV size
 * @return 1 on success, 0 on failure
 */
int crypto_geniv(uint8_t *buf, int iv_size);

/**
 * @brief Generate salt
 * 
 * @param buf The output buffer
 * @param salt_size The salt size in bytes
 * @return 1 on success, 0 on failure
 */
int crypto_gensalt(uint8_t *buf, int salt_size);

/**
 * @brief Generate a random key
 * 
 * @param buf The output buffer
 * @param key_size The key size in bytes
 * @return 1 on success, 0 on failure
 */
int crypto_genkey(uint8_t *buf, int key_size);

/**
 * @brief Transforms a secret buf into a key
 * 
 * @param buf The secret buf
 * @param buf_size The buf size
 * @param salt The salt buf
 * @param salt_size The salt buf size
 * @param key The returned key
 * @param key_size The key size
 * @return int 0 on success, -1 on failure
 */
int crypto_buf2key(uint8_t *buf, int buf_size, uint8_t *salt, int salt_size,
                   uint8_t *key, int key_size);

/**
 * @brief Encrypts a buffer with AES CBC 256
 * 
 * @param in The input buffer
 * @param in_size The input buffer size
 * @param key The 256 bit key
 * @param iv The 128 bit key
 * @param out The output buffer
 * @return The output size, -1 on error
 */
int crypto_encrypt(uint8_t *in, int in_size, uint8_t *key,
                   uint8_t *iv, uint8_t *out);

/**
 * @brief Decrypts a buffer with AES CBC 256
 * 
 * @param in The input buffer
 * @param in_size The input buffer size
 * @param key The 256 bit key
 * @param iv The 128 bit key
 * @param out The output buffer
 * @return The output size, -1 on error
 */
int crypto_decrypt(uint8_t *in, int in_size, uint8_t *key,
                   uint8_t *iv, uint8_t *out);

/**
 * @brief Generate a private RSA key string
 * 
 * @param bits Number of key bits
 * @param key The output key string
 * @return int 0 on success, -1 on failure
 */
int crypto_generate_privkey_str(int bits, char **key);

/**
 * @brief Generates a pair of private key and certificate strings
 * 
 * @param meta Certificate metadata
 * @param key The private key buffer
 * @param key_size The private key buffer size
 * @param cert The certificate string
 * @return int 0 on success, -1 on failure
 */
int crypto_generate_cert_str(struct certificate_meta *meta, uint8_t *key, size_t key_size, char **cert);

#ifdef __cplusplus
}
#endif

#endif