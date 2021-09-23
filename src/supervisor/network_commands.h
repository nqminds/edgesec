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
 * @file network_commands.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the network commands.
 */

#ifndef NETWORK_COMMANDS_H
#define NETWORK_COMMANDS_H

#include <inttypes.h>
#include <stdbool.h>

#define TICKET_PASSPHRASE_SIZE  16
#define TICKET_TIMEOUT          60  // In seconds

#include "../ap/ap_config.h"

/**
 * @brief The AP service callback
 * 
 * @param context The supervisor context
 * @param mac_addr The STA mac address
 * @param status The STA connection status
 * @return 0 on success, -1 on failure
 */
void ap_service_callback(struct supervisor_context *context, uint8_t mac_addr[], enum AP_CONNECTION_STATUS status);

/**
 * @brief Return a mac_conn_info for a given MAC address
 * 
 * @param mac_addr The input MAC adderss
 * @param mac_conn_arg The supervisor_context pointer
 * @return struct mac_conn_info 
 */
struct mac_conn_info get_mac_conn_cmd(uint8_t mac_addr[], void *mac_conn_arg);

/**
 * @brief ACCEPT_MAC command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param vlanid The VLAN ID
 * @return int 0 on success, -1 on failure
 */
int accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr, int vlanid);

/**
 * @brief DENY_MAC command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @return int 0 on success, -1 on failure
 */
int deny_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief ADD_NAT command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @return int 0 on success, -1 on failure
 */
int add_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief REMOVE_NAT command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @return int 0 on success, -1 on failure
 */
int remove_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief ASSIGN_PSK command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param pass The password
 * @param pass_len The password length
 * @return int 0 on success, -1 on failure
 */
int assign_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *pass, int pass_len);

/**
 * @brief SET_IP command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param ip_addr The IP address
 * @param add if add = true then add IP to MAC entry, otherwise remove
 * @return int 0 on success, -1 on failure
 */
int set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *ip_addr, bool add);

/**
 * @brief ADD_BRIDGE command
 * 
 * @param context The supervisor structure instance
 * @param left_mac_addr The left MAC address
 * @param right_mac_addr The right MAC address
 * @return int 0 on success, -1 on failure
 */
int add_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr);

/**
 * @brief REMOVE_BRIDGE command
 * 
 * @param context The supervisor structure instance
 * @param left_mac_addr The left MAC address
 * @param right_mac_addr The right MAC address
 * @return int 0 on success, -1 on failure
 */
int remove_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr);

/**
 * @brief SET_FINGERPRINT command
 * 
 * @param context The supervisor structure instance
 * @param src_mac_addr The source MAC address string
 * @param dst_mac_addr The destination MAC address string
 * @param protocol The protocol string
 * @param fingerprint The fingerprint string
 * @param timestamp The timestamp 64 bit value
 * @param query The query string
 * @return int 0 on success, -1 on failure
 */
int set_fingerprint_cmd(struct supervisor_context *context, char *src_mac_addr,
                        char *dst_mac_addr, char *protocol, char *fingerprint,
                        uint64_t timestamp, char *query);

/**
 * @brief QUERY_FINGERPRINT command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address string
 * @param timestamp The timestamp 64 bit value
 * @param op The operator string
 * @param protocol The protocol string
 * @param out The output string
 * @return ssize_t the sizeo fo the output buffer, -1 on failure
 */
ssize_t query_fingerprint_cmd(struct supervisor_context *context, char *mac_addr, uint64_t timestamp,
                        char *op, char *protocol, char **out);
/**
 * @brief REGISTER_TICKET command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address string
 * @param label The label string
 * @param vlanid The VLAN ID
 * @return char* passphrase string, NULL on failure
 */
uint8_t* register_ticket_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *label,
                        int vlanid);

/**
 * @brief CLEAR_PSK command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address string
 * @return 0 on success, -1 on failure
 */
int clear_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr);

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
 * @param context The supervisor structure instance
 * @param key The crypt key
 * @param value The crypt output value
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
int gen_randkey_cmd(struct supervisor_context *context, char *keyid, uint8_t size);

/**
 * @brief GEN_PRIVKEY command
 * 
 * @param context The supervisor structure instance
 * @param keyid The key id
 * @param size The key size in bytes
 * @return 0 on success, -1 on failure
 */
int gen_privkey_cmd(struct supervisor_context *context, char *keyid, uint8_t size);

/**
 * @brief GEN_PUBKEY command
 * 
 * @param context The supervisor structure instance
 * @param certid The public id
 * @param keyid The private key id
 * @return 0 on success, -1 on failure
 */
int gen_pubkey_cmd(struct supervisor_context *context, char *pubid, char *keyid);

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
char* encrypt_blob_cmd(struct supervisor_context *context, char *keyid, char *ivid, char *blob);

/**
 * @brief DECRYPT_BLOB command
 * 
 * @param context The supervisor structure instance
 * @param keyid The private key id
 * @param ivid The iv id
 * @param blob The blob base64 string to decrypt
 * @return char* the decrypted blob in base64, NULL on failure
 */
char* decrypt_blob_cmd(struct supervisor_context *context, char *keyid, char *ivid, char *blob);

/**
 * @brief SIGN_BLOB command
 * 
 * @param context The supervisor structure instance
 * @param keyid The private key id
 * @param blob The blob base64 string to sign
 * @return char* the signed blob in base64, NULL on failure
 */
char* sign_blob_cmd(struct supervisor_context *context, char *keyid, char *blob);

#endif
