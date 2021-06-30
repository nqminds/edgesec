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
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
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

// int crypto_generate_certificate(void)
// {
//   BIGNUM *bne = NULL;
// 	EVP_PKEY *pkey=NULL;
//   RSA *rsa;
  
//   if ((pkey = EVP_PKEY_new()) == NULL) {
//     log_trace("EVP_PKEY_new fail with code=%d", ERR_get_error());
//     return -1;
//   }

//   bne = BN_new();
//   if (BN_set_word(bne, RSA_F4) < 1) {
//     log_trace("BN_set_word fail");
//     EVP_PKEY_free(pkey);
//     return -1;
//   }
//   if ((rsa = RSA_new()) == NULL) {
//     log_trace("RSA_new fail");
//     EVP_PKEY_free(pkey);
//     BN_free(bne);
//     return -1;
//   }

//   if (RSA_generate_key_ex(rsa, 2048, bne, NULL) < 1) {
//     log_trace("RSA_generate_key_ex fail");
//     RSA_free(rsa);
//     EVP_PKEY_free(pkey);
//     BN_free(bne);
//     return -1;
//   }

//   if (EVP_PKEY_assign_RSA(pkey, rsa) < 1) {
//     log_trace("EVP_PKEY_assign_RSA fail");    RSA_free(rsa);
//     EVP_PKEY_free(pkey);
//     BN_free(bne);
//     return -1;
//   };

//   BIO *mem = BIO_new(BIO_s_mem());
//   BUF_MEM *ptr = NULL;
//   if (PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL) < 1) {
//     log_trace("PEM_write_bio_PrivateKey fail");
//     EVP_PKEY_free(pkey);
//     BN_free(bne);
//     return -1;
//   }
//   BIO_get_mem_ptr(mem, &ptr);
//   log_trace("%.*s", ptr->length, ptr->data);

//   X509* x509 = X509_new();
//   /* certificate expiration date: 365 days from now (60s * 60m * 24h * 365d) */
//   X509_gmtime_adj(X509_get_notBefore(x509), 0);
//   X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

//   X509_set_pubkey(x509, pkey);

//   /* set the name of the issuer to the name of the subject. */
//   X509_NAME* name = X509_get_subject_name(x509);
//   X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
//   X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"Isles of Blessed", -1, -1, 0);
//   X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)"Arkadia", -1, -1, 0);
//   X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"acme", -1, -1, 0);
//   X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"dev", -1, -1, 0);
//   X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"127.0.0.1", -1, -1, 0);

//   X509_set_issuer_name(x509, name);

//   /* finally sign the certificate with the key. */
//   X509_sign(x509, pkey, EVP_sha256());  

//   BIO *mem_x509 = BIO_new(BIO_s_mem());
//   BUF_MEM *ptr_x509 = NULL;

//   if (PEM_write_bio_X509(mem_x509, x509) < 1) {
//     log_trace("PEM_write_bio_X509 fail");
//     BIO_free(mem);
//     BIO_free(mem_x509);
//     EVP_PKEY_free(pkey);
//     BN_free(bne);
//     X509_free(x509);
//     return -1;
//   }

//   BIO_get_mem_ptr(mem_x509, &ptr_x509);
//   log_trace("%.*s", ptr_x509->length, ptr_x509->data);

//   BIO_free(mem);
//   BIO_free(mem_x509);
//   EVP_PKEY_free(pkey);
//   BN_free(bne);
//   X509_free(x509);
//   return 0;
// }