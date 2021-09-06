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
#ifdef WITH_OPENSSL_SERVICE
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#endif
#include "cryptou.h"

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/base64.h"

int crypto_geniv(uint8_t *buf, int iv_size)
{
#ifdef WITH_OPENSSL_SERVICE
  return RAND_bytes(buf, iv_size);
#else
  log_trace("crypto_geniv not implemented");
  return 0;
#endif
}

int crypto_gensalt(uint8_t *buf, int salt_size)
{
#ifdef WITH_OPENSSL_SERVICE
  return RAND_bytes(buf, salt_size);
#else
  log_trace("crypto_gensalt not implemented");
  return 0;
#endif
}

int crypto_genkey(uint8_t *buf, int key_size)
{
#ifdef WITH_OPENSSL_SERVICE
  return RAND_bytes(buf, key_size);
#else
  log_trace("crypto_genkey not implemented");
  return 0;
#endif
}

int crypto_buf2key(uint8_t *buf, int buf_size, uint8_t *salt, int salt_size,
                   uint8_t *key, int key_size)
{
#ifdef WITH_OPENSSL_SERVICE
  if (PKCS5_PBKDF2_HMAC(buf, buf_size, salt, salt_size, MAX_KEY_ITERATIONS,
                    EVP_sha256(), key_size, key) < 1) {
    log_trace("PKCS5_PBKDF2_HMAC fail wit code=%d", ERR_get_error());
    return -1;
  }

  return 0;
#else
  log_trace("crypto_buf2key not implemented");
  return -1;
#endif
}

int crypto_encrypt(uint8_t *in, int in_size, uint8_t *key,
                   uint8_t *iv, uint8_t *out)
{
#ifdef WITH_OPENSSL_SERVICE
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
#else
   log_trace("crypto_encrypt not implemented");
  return -1;
#endif
}

int crypto_decrypt(uint8_t *in, int in_size, uint8_t *key,
                   uint8_t *iv, uint8_t *out)
{
#ifdef WITH_OPENSSL_SERVICE
  EVP_CIPHER_CTX *ctx;
  
  int len = 0;
  int plaintext_len = 0;

  /* Create and initialise the context */
  if((ctx = EVP_CIPHER_CTX_new()) == NULL) {
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
#else
   log_trace("crypto_decrypt not implemented");
  return -1;
#endif
}

#ifdef WITH_OPENSSL_SERVICE
EVP_PKEY *crypto_generate_RSA_key(EVP_PKEY_CTX *ctx, int bits)
{
  EVP_PKEY *pkey = NULL;

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
    log_trace("EVP_PKEY_CTX_set_rsa_keygen_bits fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    log_trace("EVP_PKEY_keygen fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  return pkey;
}

char* crypto_generate_cert_str(EVP_PKEY *pkey)
{
  char *out;
  X509* x509 = X509_new();
  BIO *mem = BIO_new(BIO_s_mem());
  BUF_MEM *ptr = NULL;

  /* certificate expiration date: 365 days from now (60s * 60m * 24h * 365d) */
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

  X509_set_pubkey(x509, pkey);

  /* set the name of the issuer to the name of the subject. */
  X509_NAME* name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"IE", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"nqmcyber", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"R&D", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);

  X509_set_issuer_name(x509, name);

  /* finally sign the certificate with the key. */
  X509_sign(x509, pkey, EVP_sha256());  

  if (PEM_write_bio_X509(mem, x509) < 1) {
    log_trace("PEM_write_bio_X509 fail");
    BIO_free(mem);
    X509_free(x509);
    return NULL;
  }

  BIO_get_mem_ptr(mem, &ptr);
  out = (char *) os_zalloc(ptr->length + 1);
  if (out == NULL) {
    log_trace("os_zalloc failure");
    BIO_free(mem);
    X509_free(x509);
    return NULL;
  }

  os_memcpy(out, ptr->data, ptr->length);

  BIO_free(mem);
  X509_free(x509);
  return out;
}
#endif

int crypto_generate_keycert_str(int bits, char **key, char **cert)
{
#ifdef WITH_OPENSSL_SERVICE
  char *key_str = NULL, *cert_str = NULL;
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL;
  BUF_MEM *ptr = NULL;
  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (mem == NULL) {
    log_trace("BIO_new fail");
    return -1;
  }

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) <= 0) {
    log_trace("EVP_PKEY_CTX_new_id fail with code=%d", ERR_get_error());
    BIO_free(mem);
    return -1;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    log_trace("EVP_PKEY_keygen_init fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    BIO_free(mem);
    return -1;
  }

  pkey = crypto_generate_RSA_key(ctx, bits);
  if (pkey == NULL) {
    log_trace("crypto_generate_RSA_key fail");
    EVP_PKEY_CTX_free(ctx);
    BIO_free(mem);
    return -1;
  }

  if ((cert_str = crypto_generate_cert_str(pkey)) == NULL) {
    log_trace("crypto_generate_cert_str failure");
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL) < 1) {
    log_trace("PEM_write_bio_PrivateKey fail");
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  BIO_get_mem_ptr(mem, &ptr);
  key_str = (char *) os_zalloc(ptr->length + 1);
  if (key_str == NULL) {
    log_err("os_zalloc");
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  os_memcpy(key_str, ptr->data, ptr->length);

  *key = key_str;
  *cert = cert_str;

  BIO_free(mem);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return 0;
#else
  log_trace("crypto_generate_keycert_str not implemented");
  return -1;
#endif
}
