/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the cryptographic utilities.
 */

#include <stdint.h>

/*
 * Our minimum supported OpenSSL version is v1.1.1
 * (Ubuntu 20.04).
 * See https://www.openssl.org/docs/man3.1/man7/openssl_user_macros.html
 */
#define OPENSSL_API_COMPAT 10101
// don't show deprecated OpenSSL funcs
#define OPENSSL_NO_DEPRECATED 1

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include "cryptou.h"

#include "../utils/allocs.h"
#include "../utils/log.h"
#include "../utils/os.h"

int crypto_geniv(uint8_t *buf, int iv_size) { return RAND_bytes(buf, iv_size); }

int crypto_gensalt(uint8_t *buf, int salt_size) {
  return RAND_bytes(buf, salt_size);
}

int crypto_genkey(uint8_t *buf, int key_size) {
  return RAND_bytes(buf, key_size);
}

int crypto_buf2key(const uint8_t *buf, int buf_size, const uint8_t *salt,
                   int salt_size, uint8_t *key, int key_size) {
  if (PKCS5_PBKDF2_HMAC((char *)buf, buf_size, salt, salt_size,
                        MAX_KEY_ITERATIONS, EVP_sha256(), key_size, key) < 1) {
    log_trace("PKCS5_PBKDF2_HMAC fail wit code=%lu", ERR_get_error());
    return -1;
  }

  return 0;
}

ssize_t crypto_encrypt(const uint8_t *in, int in_size, const uint8_t *key,
                       const uint8_t *iv, uint8_t *out) {
  EVP_CIPHER_CTX *ctx;
  int len;
  ssize_t ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    log_trace("EVP_CIPHER_CTX_new fail with code=%lu", ERR_get_error());
    return -1;
  }

  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    log_trace("EVP_EncryptInit_ex fail with code=%lu", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, out, &len, in, in_size)) {
    log_trace("EVP_EncryptUpdate fail with code=%lu", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  ciphertext_len = len;

  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
    log_trace("EVP_EncryptFinal_ex fail with code=%lu", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

ssize_t crypto_decrypt(uint8_t *in, int in_size, uint8_t *key, uint8_t *iv,
                       uint8_t *out) {
  EVP_CIPHER_CTX *ctx;

  int len = 0;
  int plaintext_len = 0;

  /* Create and initialise the context */
  if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
    log_trace("EVP_CIPHER_CTX_new fail with code=%lu", ERR_get_error());
    return -1;
  }

  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    log_trace("EVP_DecryptInit_ex fail with code=%lu", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, out, &len, in, in_size)) {
    log_trace("EVP_DecryptUpdate fail with code=%lu", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  plaintext_len = len;

  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) {
    log_trace("EVP_DecryptFinal_ex fail with code=%lu", ERR_get_error());
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

EVP_PKEY *crypto_generate_rsa_key(int bits) {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL;

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
    log_trace("EVP_PKEY_CTX_new_id fail with code=%lu", ERR_get_error());
    return NULL;
  }

  if (!EVP_PKEY_keygen_init(ctx)) {
    log_trace("EVP_PKEY_keygen_init fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (!EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)) {
    log_trace("EVP_PKEY_CTX_set_rsa_keygen_bits fail with code=%lu",
              ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    log_trace("EVP_PKEY_keygen fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

EVP_PKEY *crypto_generate_ec_key(void) {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL, *params = NULL;

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL) {
    log_trace("EVP_PKEY_CTX_new_id fail with code=%lu", ERR_get_error());
    return NULL;
  }

  if (!EVP_PKEY_paramgen_init(ctx)) {
    log_trace("EVP_PKEY_paramgen_init fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1)) {
    log_trace("EVP_PKEY_CTX_set_ec_paramgen_curve_nid fail with code=%lu",
              ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (!EVP_PKEY_paramgen(ctx, &params)) {
    log_trace("EVP_PKEY_paramgen fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);

  if ((ctx = EVP_PKEY_CTX_new(params, NULL)) == NULL) {
    log_trace("EVP_PKEY_CTX_new fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(params);
    return NULL;
  }

  EVP_PKEY_free(params);

  if (!EVP_PKEY_keygen_init(ctx)) {
    log_trace("EVP_PKEY_keygen_init fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    log_trace("EVP_PKEY_keygen fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

X509 *crypto_generate_cert(EVP_PKEY *pkey, struct certificate_meta *meta) {
  X509 *x509 = X509_new();

  if (x509 == NULL) {
    log_trace("X509_new fail");
    return NULL;
  }

  /* certificate expiration date: 365 days from now (60s * 60m * 24h * 365d) */
  X509_gmtime_adj(X509_getm_notBefore(x509), meta->not_before);
  X509_gmtime_adj(X509_getm_notAfter(x509), meta->not_after);

  if (!X509_set_pubkey(x509, pkey)) {
    log_trace("X509_set_pubkey fail with code=%lu", ERR_get_error());
    X509_free(x509);
    return NULL;
  }

  /* set the name of the issuer to the name of the subject. */
  X509_NAME *name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)meta->c,
                             -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)meta->o,
                             -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                             (unsigned char *)meta->ou, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (unsigned char *)meta->cn, -1, -1, 0);

  X509_set_issuer_name(x509, name);

  /* sign the certificate with the key. */
  if (!X509_sign(x509, pkey, EVP_sha256())) {
    log_trace("X509_sign fail with code=%lu", ERR_get_error());
    X509_free(x509);
    return NULL;
  }

  return x509;
}

EVP_PKEY *crypto_key2evp(uint8_t *key, size_t key_size) {
  EVP_PKEY *pkey = NULL;
  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (BIO_write(mem, key, key_size) < 0) {
    log_trace("BIO_write fail with code=%lu", ERR_get_error());
    BIO_free(mem);
    return NULL;
  }

  if ((pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL)) == NULL) {
    log_trace("PEM_read_bio_PrivateKey fail with code=%lu", ERR_get_error());
    BIO_free(mem);
    return NULL;
  }

  BIO_free(mem);
  return pkey;
}

EVP_PKEY *crypto_priv2pub(EVP_PKEY *key) {
  EVP_PKEY *pubkey = NULL;
  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (mem == NULL) {
    log_trace("BIO_new_ex fail");
    return NULL;
  }

  /* Write pubkey to the bio  */
  if (!PEM_write_bio_PUBKEY(mem, key)) {
    log_trace("PEM_write_bio_PUBKEY fail with code=%lu", ERR_get_error());
    BIO_free(mem);
    return NULL;
  }

  /* Get pubkey */
  if ((pubkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL)) == NULL) {
    log_trace("PEM_read_bio_PUBKEY fail with code=%lu", ERR_get_error());
    BIO_free(mem);
    return NULL;
  }

  /* Free */
  BIO_free(mem);
  return pubkey;
}

char *crypto_get_key_str(bool private, EVP_PKEY *pkey) {
  char *key_str = NULL;
  BUF_MEM *ptr = NULL;
  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (mem == NULL) {
    log_trace("BIO_new fail");
    return NULL;
  }

  if (private) {
    if (!PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL)) {
      log_trace("PEM_write_bio_PrivateKey fail with code=%lu", ERR_get_error());
      BIO_free(mem);
      return NULL;
    }
  } else {
    if (!PEM_write_bio_PUBKEY(mem, pkey)) {
      log_trace("PEM_write_bio_PUBKEY fail with code=%lu", ERR_get_error());
      BIO_free(mem);
      return NULL;
    }
  }

  BIO_get_mem_ptr(mem, &ptr);
  if ((key_str = (char *)os_zalloc(ptr->length + 1)) == NULL) {
    log_errno("os_zalloc");
    BIO_free(mem);
    return NULL;
  }

  os_memcpy(key_str, ptr->data, ptr->length);

  BIO_free(mem);
  return key_str;
}

int crypto_generate_privkey_str(enum CRYPTO_KEY_TYPE type, int bits,
                                char **key) {
  EVP_PKEY *pkey = NULL;

  switch (type) {
    case CRYPTO_KEY_RSA:
      if ((pkey = crypto_generate_rsa_key(bits)) == NULL) {
        log_trace("crypto_generate_RSA_key fail");
        return -1;
      }
      break;
    default:
      if ((pkey = crypto_generate_ec_key()) == NULL) {
        log_trace("crypto_generate_ec_key fail");
        return -1;
      }
  }

  if ((*key = crypto_get_key_str(true, pkey)) == NULL) {
    log_trace("crypto_get_key_str fail");
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_free(pkey);
  return 0;
}

int crypto_generate_pubkey_str(uint8_t *key, size_t key_size, char **pub) {
  EVP_PKEY *pubkey = NULL;
  EVP_PKEY *privkey = crypto_key2evp(key, key_size);

  *pub = NULL;

  if (privkey == NULL) {
    log_trace("crypto_key2evp fail");
    return -1;
  }

  if ((pubkey = crypto_priv2pub(privkey)) == NULL) {
    log_trace("crypto_priv2pub fail");
    EVP_PKEY_free(privkey);
    return -1;
  }

  if ((*pub = crypto_get_key_str(false, pubkey)) == NULL) {
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
    return 0;
  }

  EVP_PKEY_free(privkey);
  EVP_PKEY_free(pubkey);
  return 0;
}

int crypto_generate_cert_str(struct certificate_meta *meta, uint8_t *key,
                             size_t key_size, char **cert) {
  X509 *x509 = NULL;
  EVP_PKEY *pkey = NULL;
  BUF_MEM *ptr = NULL;
  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (mem == NULL) {
    log_trace("BIO_new_ex fail");
    return -1;
  }

  if ((pkey = crypto_key2evp(key, key_size)) == NULL) {
    BIO_free(mem);
    return -1;
  }

  if ((x509 = crypto_generate_cert(pkey, meta)) == NULL) {
    log_trace("crypto_generate_cert fail");
    EVP_PKEY_free(pkey);
    BIO_free(mem);
    return -1;
  }

  if (PEM_write_bio_X509(mem, x509) < 1) {
    log_trace("PEM_write_bio_X509 fail with code=%lu", ERR_get_error());
    X509_free(x509);
    EVP_PKEY_free(pkey);
    BIO_free(mem);
    return -1;
  }

  BIO_get_mem_ptr(mem, &ptr);
  if ((*cert = (char *)os_zalloc(ptr->length + 1)) == NULL) {
    log_errno("os_zalloc");
    X509_free(x509);
    EVP_PKEY_free(pkey);
    BIO_free(mem);
    return -1;
  }

  os_memcpy(*cert, ptr->data, ptr->length);

  X509_free(x509);
  EVP_PKEY_free(pkey);
  BIO_free(mem);
  return 0;
}

int crypto_verify_data(uint8_t *key, size_t key_size, uint8_t *in,
                       size_t in_size, uint8_t *sig, size_t sig_size) {
  EVP_MD_CTX *ctx = NULL;
  EVP_PKEY *pubkey = NULL;
  EVP_PKEY *privkey = crypto_key2evp(key, key_size);

  if (privkey == NULL) {
    log_trace("crypto_key2evp fail");
    return -1;
  }

  if ((pubkey = crypto_priv2pub(privkey)) == NULL) {
    log_trace("crypto_priv2pub fail");
    EVP_PKEY_free(privkey);
    return -1;
  }

  /* Create the Message Digest Context */
  if ((ctx = EVP_MD_CTX_create()) == NULL) {
    log_trace("EVP_MD_CTX_create fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
    return -1;
  }

  /* Initialize `key` with a public key */
  if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey)) {
    log_trace("EVP_DigestVerifyInit fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  if (!EVP_DigestVerifyUpdate(ctx, in, in_size)) {
    log_trace("EVP_DigestVerifyUpdate fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  if (EVP_DigestVerifyFinal(ctx, sig, sig_size) != 1) {
    log_trace("EVP_DigestVerifyFinal fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  EVP_PKEY_free(privkey);
  EVP_PKEY_free(pubkey);
  EVP_MD_CTX_destroy(ctx);
  return 0;
}

ssize_t crypto_sign_data(uint8_t *key, size_t key_size, uint8_t *in,
                         size_t in_size, uint8_t **out) {
  size_t sig_len = -1;
  EVP_MD_CTX *ctx = NULL;
  uint8_t *out_sig = NULL;
  const EVP_MD *md = EVP_get_digestbyname("SHA256");
  EVP_PKEY *pkey = crypto_key2evp(key, key_size);

  *out = NULL;

  if (pkey == NULL) {
    log_trace("crypto_key2evp fail");
    return -1;
  }

  if ((ctx = EVP_MD_CTX_create()) == NULL) {
    log_trace("EVP_MD_CTX_create fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(pkey);
    return -1;
  }

  /* Initialise the DigestSign operation with SHA-256 as the message digest
   * function */
  if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
    log_trace("EVP_DigestSignInit fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  /* Call update with the message */
  if (EVP_DigestSignUpdate(ctx, in, in_size) != 1) {
    log_trace("EVP_DigestSignUpdate fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  /* Finalise the DigestSign operation */
  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the
   * length of the signature.*/
  if (EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1) {
    log_trace("EVP_DigestSignFinal fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  if ((out_sig = os_malloc(sizeof(unsigned char) * (sig_len))) == NULL) {
    log_errno("os_malloc");
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  /* Obtain the signature */
  if (EVP_DigestSignFinal(ctx, out_sig, &sig_len) != 1) {
    log_trace("EVP_DigestSignFinal fail with code=%lu", ERR_get_error());
    os_free(out_sig);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  if (crypto_verify_data(key, key_size, in, in_size, out_sig, sig_len) < 0) {
    log_trace("crypto_verify_data fail");
    os_free(out_sig);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);
    return -1;
  }

  *out = out_sig;
  EVP_PKEY_free(pkey);
  EVP_MD_CTX_destroy(ctx);
  return sig_len;
}
