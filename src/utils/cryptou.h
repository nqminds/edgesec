/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file cryptou.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the cryptographic utilities.
 */

#ifndef CRYPTOU_H
#define CRYPTOU_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define AES_BLOCK_SIZE 16
#define IV_SIZE AES_BLOCK_SIZE
#define SALT_SIZE 16
#define AES_KEY_SIZE 32
#define MAX_KEY_ITERATIONS 1000

#define MAX_CERT_FIELD_SIZE 64

struct certificate_meta {
  long not_before;
  long not_after;
  char c[MAX_CERT_FIELD_SIZE];
  char o[MAX_CERT_FIELD_SIZE];
  char ou[MAX_CERT_FIELD_SIZE];
  char cn[MAX_CERT_FIELD_SIZE];
};

enum CRYPTO_KEY_TYPE { CRYPTO_KEY_NONE = 0, CRYPTO_KEY_RSA, CRYPTO_KEY_EC };

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
ssize_t crypto_encrypt(uint8_t *in, int in_size, uint8_t *key, uint8_t *iv,
                       uint8_t *out);

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
ssize_t crypto_decrypt(uint8_t *in, int in_size, uint8_t *key, uint8_t *iv,
                       uint8_t *out);

/**
 * @brief Generate a private RSA key string
 *
 * @param type The key type
 * @param bits Number of key bits
 * @param key The output key string
 * @return int 0 on success, -1 on failure
 */
int crypto_generate_privkey_str(enum CRYPTO_KEY_TYPE type, int bits,
                                char **key);

/**
 * @brief Generates a public key string from a private key
 *
 * @param key The private key buffer
 * @param key_size The private key buffer size
 * @param pub The public key string
 * @return int 0 on success, -1 on failure
 */
int crypto_generate_pubkey_str(uint8_t *key, size_t key_size, char **pub);

/**
 * @brief Generates a pair of private key and certificate strings
 *
 * @param meta Certificate metadata
 * @param key The private key buffer
 * @param key_size The private key buffer size
 * @param cert The certificate string
 * @return int 0 on success, -1 on failure
 */
int crypto_generate_cert_str(struct certificate_meta *meta, uint8_t *key,
                             size_t key_size, char **cert);

/**
 * @brief Signs a buffer with a private key string
 *
 * @param key The private key buffer
 * @param key_size The private key buffer size
 * @param in The input buffer
 * @param in_size The input buffer size
 * @param out The output signature
 * @return ssize_t the length of the signature, -1 on failure
 */
ssize_t crypto_sign_data(uint8_t *key, size_t key_size, uint8_t *in,
                         size_t in_size, uint8_t **out);
#endif
