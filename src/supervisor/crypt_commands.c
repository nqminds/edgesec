/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @brief File containing the implementation of the crypt commands.
 */

#include <libgen.h>

#include "mac_mapper.h"
#include "supervisor.h"
#include "sqlite_macconn_writer.h"
#include "network_commands.h"

#include "../ap/ap_config.h"
#include "../ap/ap_service.h"
#include "../crypt/crypt_service.h"
#include "../capture/capture_service.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/base64.h"
#include "../utils/eloop.h"

int put_crypt_cmd(struct supervisor_context *context, char *key, char *value) {
  struct crypt_pair pair = {key, NULL, 0};

  log_trace("PUT_CRYPT for key=%s", key);

  if ((pair.value =
           (uint8_t *)base64_url_decode((unsigned char *)value, strlen(value),
                                        (size_t *)&pair.value_size)) == NULL) {
    log_trace("base64_url_decode fail");
    return -1;
  }

  if (put_crypt_pair(context->crypt_ctx, &pair) < 0) {
    log_trace("put_crypt_pair fail");
    os_free(pair.value);
    return -1;
  }

  os_free(pair.value);
  return 0;
}

int get_crypt_cmd(struct supervisor_context *context, char *key, char **value) {
  struct crypt_pair *pair = NULL;
  size_t out_len;

  log_trace("GET_CRYPT for key=%s", key);

  *value = NULL;

  if ((pair = get_crypt_pair(context->crypt_ctx, key)) == NULL) {
    log_trace("get_crypt_pair fail");
    return -1;
  }

  if (pair->value == NULL) {
    log_trace("Empty value");
    free_crypt_pair(pair);
    return -1;
  }

  if ((*value = (char *)base64_url_encode(pair->value, pair->value_size,
                                          &out_len, 0)) == NULL) {
    log_trace("base64_url_encode fail");
    free_crypt_pair(pair);
    return -1;
  }

  free_crypt_pair(pair);
  return 0;
}

int gen_randkey_cmd(struct supervisor_context *context, char *keyid,
                    uint8_t size) {
  struct crypt_pair pair = {keyid, NULL, (ssize_t)size};

  log_trace("GEN_RANDKEY for key=%s and size=%d", keyid, size);

  if ((pair.value = os_malloc(pair.value_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }
  if (crypto_genkey(pair.value, pair.value_size) < 0) {
    log_trace("crypto_genkey fail");
    os_free(pair.value);
    return -1;
  }

  if (put_crypt_pair(context->crypt_ctx, &pair) < 0) {
    log_trace("put_crypt_pair fail");
    os_free(pair.value);
    return -1;
  }

  os_free(pair.value);

  return 0;
}

int gen_privkey_cmd(struct supervisor_context *context, char *keyid,
                    uint8_t size) {
  struct crypt_pair pair = {keyid, NULL, (ssize_t)size};

  log_trace("GEN_PRIVKEY for key=%s and size=%d", keyid, size);

  if (crypto_generate_privkey_str(CRYPTO_KEY_EC, size * 8,
                                  (char **)&pair.value) < 0) {
    log_trace("crypto_generate_privkey_str fail");
    return -1;
  }

  pair.value_size = strlen((char *)pair.value);

  if (put_crypt_pair(context->crypt_ctx, &pair) < 0) {
    log_trace("put_crypt_pair fail");
    os_free(pair.value);
    return -1;
  }

  os_free(pair.value);

  return 0;
}

int gen_pubkey_cmd(struct supervisor_context *context, char *pubid,
                   char *keyid) {
  struct crypt_pair *pair = NULL;
  struct crypt_pair pub_pair = {pubid, NULL, 0};

  log_trace("GEN_PUBKEY for pubid=%s and keyid=%s", pubid, keyid);

  if ((pair = get_crypt_pair(context->crypt_ctx, keyid)) == NULL) {
    log_trace("get_crypt_pair fail");
    return -1;
  }

  if (crypto_generate_pubkey_str(pair->value, pair->value_size,
                                 (char **)&pub_pair.value) < 0) {
    log_trace("crypto_generate_pubkey_str fail");
    free_crypt_pair(pair);
    return -1;
  }
  free_crypt_pair(pair);

  pub_pair.value_size = strlen((char *)pub_pair.value);

  if (put_crypt_pair(context->crypt_ctx, &pub_pair) < 0) {
    log_trace("put_crypt_pair fail");
    os_free(pub_pair.value);
    return -1;
  }

  os_free(pub_pair.value);
  return 0;
}

int gen_cert_cmd(struct supervisor_context *context, char *certid, char *keyid,
                 struct certificate_meta *meta) {
  struct crypt_pair *pair = NULL;
  struct crypt_pair cert_pair = {certid, NULL, 0};

  log_trace("GEN_CERT for certid=%s and keyid=%s", certid, keyid);

  if ((pair = get_crypt_pair(context->crypt_ctx, keyid)) == NULL) {
    log_trace("get_crypt_pair fail");
    return -1;
  }

  if (crypto_generate_cert_str(meta, pair->value, pair->value_size,
                               (char **)&cert_pair.value) < 0) {
    log_trace("crypto_generate_cert_str fail");
    free_crypt_pair(pair);
    return -1;
  }
  free_crypt_pair(pair);

  cert_pair.value_size = strlen((char *)cert_pair.value);

  if (put_crypt_pair(context->crypt_ctx, &cert_pair) < 0) {
    log_trace("put_crypt_pair fail");
    os_free(cert_pair.value);
    return -1;
  }

  os_free(cert_pair.value);
  return 0;
}

char *encrypt_blob_cmd(struct supervisor_context *context, char *keyid,
                       char *ivid, char *blob) {
  struct crypt_pair *keypair = NULL, *ivpair = NULL;
  uint8_t *blob_data = NULL, *encrypted_data = NULL;
  size_t blob_data_size;
  ssize_t encrypted_size;
  char *encrypted_str = NULL;
  log_trace("ENCRYPT_BLOB with keyid=%s and ivid=%s", keyid, ivid);

  if ((keypair = get_crypt_pair(context->crypt_ctx, keyid)) == NULL) {
    log_trace("get_crypt_pair fail");
    return NULL;
  }

  if (keypair->value == NULL) {
    log_trace("value is empty");
    free_crypt_pair(keypair);
    return NULL;
  }

  if ((ivpair = get_crypt_pair(context->crypt_ctx, ivid)) == NULL) {
    log_trace("get_crypt_pair fail");
    free_crypt_pair(keypair);
    return NULL;
  }

  if (ivpair->value == NULL) {
    log_trace("value is empty");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    return NULL;
  }

  if ((blob_data = (uint8_t *)base64_url_decode(
           (unsigned char *)blob, strlen(blob), &blob_data_size)) == NULL) {
    log_trace("base64_url_decode fail");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    return NULL;
  }

  if ((encrypted_data = os_malloc(blob_data_size + AES_BLOCK_SIZE)) == NULL) {
    log_errno("os_malloc");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    os_free(blob_data);
    return NULL;
  }

  if ((encrypted_size =
           crypto_encrypt(blob_data, blob_data_size, keypair->value,
                          ivpair->value, encrypted_data)) < 0) {
    log_trace("crypto_encrypt fail");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    os_free(blob_data);
    return NULL;
  }

  free_crypt_pair(keypair);
  free_crypt_pair(ivpair);
  os_free(blob_data);

  if ((encrypted_str = (char *)base64_url_encode(encrypted_data, encrypted_size,
                                                 &blob_data_size, 0)) == NULL) {
    log_trace("base64_url_encode fail");
    os_free(encrypted_data);
    return NULL;
  }

  os_free(encrypted_data);
  return encrypted_str;
}

char *decrypt_blob_cmd(struct supervisor_context *context, char *keyid,
                       char *ivid, char *blob) {
  struct crypt_pair *keypair = NULL, *ivpair = NULL;
  uint8_t *blob_data = NULL, *decrypted_data = NULL;
  size_t blob_data_size;
  ssize_t decrypted_size;
  char *decrypted_str = NULL;
  log_trace("DECRYPT_BLOB with keyid=%s and ivid=%s", keyid, ivid);

  if ((keypair = get_crypt_pair(context->crypt_ctx, keyid)) == NULL) {
    log_trace("get_crypt_pair fail");
    return NULL;
  }

  if (keypair->value == NULL) {
    log_trace("value is empty");
    free_crypt_pair(keypair);
    return NULL;
  }

  if ((ivpair = get_crypt_pair(context->crypt_ctx, ivid)) == NULL) {
    log_trace("get_crypt_pair fail");
    free_crypt_pair(keypair);
    return NULL;
  }

  if (ivpair->value == NULL) {
    log_trace("value is empty");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    return NULL;
  }

  if ((blob_data = (uint8_t *)base64_url_decode(
           (unsigned char *)blob, strlen(blob), &blob_data_size)) == NULL) {
    log_trace("base64_url_decode fail");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    return NULL;
  }

  if ((decrypted_data = os_malloc(blob_data_size + AES_BLOCK_SIZE)) == NULL) {
    log_errno("os_malloc");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    os_free(blob_data);
    return NULL;
  }

  if ((decrypted_size =
           crypto_decrypt(blob_data, blob_data_size, keypair->value,
                          ivpair->value, decrypted_data)) < 0) {
    log_trace("crypto_decrypt fail");
    free_crypt_pair(keypair);
    free_crypt_pair(ivpair);
    os_free(blob_data);
    return NULL;
  }

  free_crypt_pair(keypair);
  free_crypt_pair(ivpair);
  os_free(blob_data);

  if ((decrypted_str = (char *)base64_url_encode(decrypted_data, decrypted_size,
                                                 &blob_data_size, 0)) == NULL) {
    log_trace("base64_url_encode fail");
    os_free(decrypted_data);
    return NULL;
  }

  os_free(decrypted_data);
  return decrypted_str;
}

char *sign_blob_cmd(struct supervisor_context *context, const char *keyid,
                    const char *blob) {
  struct crypt_pair *pair = NULL;
  uint8_t *blob_data = NULL, *signed_data = NULL;
  size_t blob_data_size;
  ssize_t signed_size;
  char *signed_str = NULL;
  log_trace("SIGN_BLOB with keyid=%s", keyid);

  if ((pair = get_crypt_pair(context->crypt_ctx, keyid)) == NULL) {
    log_trace("get_crypt_pair fail");
    return NULL;
  }

  if (pair->value == NULL) {
    log_trace("value is empty");
    free_crypt_pair(pair);
    return NULL;
  }

  if ((blob_data = (uint8_t *)base64_url_decode(
           (unsigned char *)blob, strlen(blob), &blob_data_size)) == NULL) {
    log_trace("base64_url_decode fail");
    free_crypt_pair(pair);
    return NULL;
  }

  if ((signed_size = crypto_sign_data(pair->value, pair->value_size, blob_data,
                                      blob_data_size, &signed_data)) < 0) {
    log_trace("crypto_sign_data fail");
    os_free(blob_data);
    free_crypt_pair(pair);
    return NULL;
  }

  os_free(blob_data);
  free_crypt_pair(pair);

  if ((signed_str = (char *)base64_url_encode(signed_data, signed_size,
                                              &blob_data_size, 0)) == NULL) {
    log_trace("base64_url_encode fail");
    os_free(signed_data);
    return NULL;
  }

  os_free(signed_data);
  return signed_str;
}
