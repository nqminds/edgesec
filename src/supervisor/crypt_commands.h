/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the definition of the crypt commands.
 */

#ifndef CRYPT_COMMANDS_H
#define CRYPT_COMMANDS_H

#include <inttypes.h>
#include <stdbool.h>

/**
 * @brief PUT_CRYPT command
 *
 * @param context The supervisor structure instance
 * @param key The crypt key
 * @param value The crypt value
 * @return 0 on success, -1 on failure
 */
int put_crypt_cmd(struct supervisor_context *context, char *key, char *value);

/**
 * @brief GET_CRYPT command
 *
 * Sets `value` to point new string containing the crypt output value.
 * Please remember to `os_free()` the `value` when you're finished with using
 * it.
 *
 * @param[in] context The supervisor structure instance
 * @param[in] key The crypt key
 * @param[out] value Pointer to crypt output value
 * @return 0 on success, -1 on failure
 */
int get_crypt_cmd(struct supervisor_context *context, char *key, char **value);

/**
 * @brief GEN_RANDKEY command
 *
 * @param context The supervisor structure instance
 * @param keyid The key id
 * @param size The key size in bytes
 * @return 0 on success, -1 on failure
 */
int gen_randkey_cmd(struct supervisor_context *context, char *keyid,
                    uint8_t size);

/**
 * @brief GEN_PRIVKEY command
 *
 * @param context The supervisor structure instance
 * @param keyid The key id
 * @param size The key size in bytes
 * @return 0 on success, -1 on failure
 */
int gen_privkey_cmd(struct supervisor_context *context, char *keyid,
                    uint8_t size);

/**
 * @brief GEN_PUBKEY command
 *
 * @param context The supervisor structure instance
 * @param certid The public id
 * @param keyid The private key id
 * @return 0 on success, -1 on failure
 */
int gen_pubkey_cmd(struct supervisor_context *context, char *pubid,
                   char *keyid);

/**
 * @brief GEN_CERT command
 *
 * @param context The supervisor structure instance
 * @param certid The certificate id
 * @param keyid The private key id
 * @param meta The certificate metadata
 * @return 0 on success, -1 on failure
 */
int gen_cert_cmd(struct supervisor_context *context, char *certid, char *keyid,
                 struct certificate_meta *meta);

/**
 * @brief ENCRYPT_BLOB command
 *
 * @param context The supervisor structure instance
 * @param keyid The private key id
 * @param ivid The iv id
 * @param blob The blob base64 string to encrypt
 * @return char* the encrypted blob in base64, NULL on failure
 */
char *encrypt_blob_cmd(struct supervisor_context *context, char *keyid,
                       char *ivid, char *blob);

/**
 * @brief DECRYPT_BLOB command
 *
 * @param context The supervisor structure instance
 * @param keyid The private key id
 * @param ivid The iv id
 * @param blob The blob base64 string to decrypt
 * @return char* the decrypted blob in base64, NULL on failure
 */
char *decrypt_blob_cmd(struct supervisor_context *context, char *keyid,
                       char *ivid, char *blob);

/**
 * @brief SIGN_BLOB command
 *
 * @param context The supervisor structure instance
 * @param keyid The private key id
 * @param blob The blob base64 string to sign
 * @return char* the signed blob in base64, NULL on failure
 */
char *sign_blob_cmd(struct supervisor_context *context, const char *keyid,
                    const char *blob);

#endif
