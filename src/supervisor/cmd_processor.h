/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the definition of the command processor functions.
 */

#ifndef CMD_PROCESSOR_H
#define CMD_PROCESSOR_H

#include <sys/un.h>
#include <sys/types.h>
#include <stdbool.h>

#include "../utils/utarray.h"
#include "../utils/sockctl.h"

#include "supervisor_config.h"

// SYSTEM commands
#define CMD_PING "PING_SUPERVISOR"
#define CMD_SET_IP "SET_IP"
#define CMD_SUBSCRIBE_EVENTS "SUBSCRIBE_EVENTS"

// NETCON commands
#define CMD_ACCEPT_MAC "ACCEPT_MAC"
#define CMD_DENY_MAC "DENY_MAC"
#define CMD_ADD_NAT "ADD_NAT"
#define CMD_REMOVE_NAT "REMOVE_NAT"
#define CMD_ASSIGN_PSK "ASSIGN_PSK"
#define CMD_GET_MAP "GET_MAP"
#define CMD_GET_ALL "GET_ALL"
#define CMD_ADD_BRIDGE "ADD_BRIDGE"
#define CMD_REMOVE_BRIDGE "REMOVE_BRIDGE"
#define CMD_CLEAR_BRIDGES "CLEAR_BRIDGE"
#define CMD_GET_BRIDGES "GET_BRIDGES"
#define CMD_REGISTER_TICKET "REGISTER_TICKET"
#define CMD_CLEAR_PSK "CLEAR_PSK"

// NETMON commands
#define CMD_SET_ALERT "SET_ALERT"
#define CMD_SET_FINGERPRINT "SET_FINGERPRINT"
#define CMD_QUERY_FINGERPRINT "QUERY_FINGERPRINT"

#ifdef WITH_CRYPTO_SERVICE
// CRYPT commands
#define CMD_PUT_CRYPT "PUT_CRYPT"
#define CMD_GET_CRYPT "GET_CRYPT"
#define CMD_GEN_RANDKEY "GEN_RANDKEY"
#define CMD_GEN_PRIVKEY "GEN_PRIVKEY"
#define CMD_GEN_PUBKEY "GEN_PUBKEY"
#define CMD_GEN_CERT "GEN_CERT"
#define CMD_ENCRYPT_BLOB "ENCRYPT_BLOB"
#define CMD_DECRYPT_BLOB "DECRYPT_BLOB"
#define CMD_SIGN_BLOB "SIGN_BLOB"
#endif

#define CMD_DELIMITER '\x20'

#define OK_REPLY "OK\n"
#define FAIL_REPLY "FAIL\n"

#define MAX_QUERY_OP_LEN 3

typedef ssize_t (*process_cmd_fn)(int sock, struct client_address *client_addr,
                                  struct supervisor_context *context,
                                  UT_array *cmd_arr);

/**
 * @brief Processes the domain command string
 *
 * @param domain_buffer The domain command string
 * @param domain_buffer_len The domain command string length
 * @param cmd_arr The processed command array
 * @param sep The string separator
 * @return true on success, false otherwise
 */
bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len,
                           UT_array *cmd_arr, char sep);

/**
 * @brief Processes the PING command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_ping_cmd(int sock, struct client_address *client_addr,
                         struct supervisor_context *context, UT_array *cmd_arr);

/**
 * @brief Processes the SUBSCRIBE_EVENTS command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_subscribe_events_cmd(int sock,
                                     struct client_address *client_addr,
                                     struct supervisor_context *context,
                                     UT_array *cmd_arr);

/**
 * @brief Processes the ACCEPT_MAC command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_accept_mac_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr);

/**
 * @brief Processes the DENY_MAC command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_deny_mac_cmd(int sock, struct client_address *client_addr,
                             struct supervisor_context *context,
                             UT_array *cmd_arr);

/**
 * @brief Processes the ADD_NAT command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_add_nat_cmd(int sock, struct client_address *client_addr,
                            struct supervisor_context *context,
                            UT_array *cmd_arr);

/**
 * @brief Processes the REMOVE_NAT command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_remove_nat_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr);

/**
 * @brief Processes the ASSIGN_PSK command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_assign_psk_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr);

/**
 * @brief Processes the GET_MAP command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_get_map_cmd(int sock, struct client_address *client_addr,
                            struct supervisor_context *context,
                            UT_array *cmd_arr);

/**
 * @brief Processes the GET_ALL command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_get_all_cmd(int sock, struct client_address *client_addr,
                            struct supervisor_context *context,
                            UT_array *cmd_arr);

/**
 * @brief Processes the SET_IP command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_set_ip_cmd(int sock, struct client_address *client_addr,
                           struct supervisor_context *context,
                           UT_array *cmd_arr);

/**
 * @brief Processes the ADD_BRIDGE command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_add_bridge_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr);

/**
 * @brief Processes the REMOVE_BRIDGE command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_remove_bridge_cmd(int sock, struct client_address *client_addr,
                                  struct supervisor_context *context,
                                  UT_array *cmd_arr);

/**
 * @brief Processes the CLEAR_BRIDGES command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_clear_bridges_cmd(int sock, struct client_address *client_addr,
                                  struct supervisor_context *context,
                                  UT_array *cmd_arr);

/**
 * @brief Processes the GET_BRIDGES command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_get_bridges_cmd(int sock, struct client_address *client_addr,
                                struct supervisor_context *context,
                                UT_array *cmd_arr);

/**
 * @brief Processes the SET_FINGERPRINT command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_set_fingerprint_cmd(int sock,
                                    struct client_address *client_addr,
                                    struct supervisor_context *context,
                                    UT_array *cmd_arr);

/**
 * @brief Processes the QUERY_FINGERPRINT command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_query_fingerprint_cmd(int sock,
                                      struct client_address *client_addr,
                                      struct supervisor_context *context,
                                      UT_array *cmd_arr);

/**
 * @brief Processes the REGISTER_TICKET command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return Size of reply written data.
 * This would be the length of the passphrase.
 * Returns `strlen(FAIL_REPLY)` on error.
 */
ssize_t process_register_ticket_cmd(int sock,
                                    struct client_address *client_addr,
                                    struct supervisor_context *context,
                                    UT_array *cmd_arr);

/**
 * @brief Processes the CLEAR_PSK command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_clear_psk_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr);

#ifdef WITH_CRYPTO_SERVICE
/**
 * @brief Processes the PUT_CRYPT command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_put_crypt_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr);

/**
 * @brief Processes the GET_CRYPT command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_get_crypt_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr);

/**
 * @brief Processes the GEN_RANDKEY command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_gen_randkey_cmd(int sock, struct client_address *client_addr,
                                struct supervisor_context *context,
                                UT_array *cmd_arr);

/**
 * @brief Processes the GEN_PRIVKEY command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_gen_privkey_cmd(int sock, struct client_address *client_addr,
                                struct supervisor_context *context,
                                UT_array *cmd_arr);

/**
 * @brief Processes the GEN_PUBKEY command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_gen_pubkey_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr);

/**
 * @brief Processes the GEN_CERT command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_gen_cert_cmd(int sock, struct client_address *client_addr,
                             struct supervisor_context *context,
                             UT_array *cmd_arr);

/**
 * @brief Processes the ENCRYPT_BLOB command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_encrypt_blob_cmd(int sock, struct client_address *client_addr,
                                 struct supervisor_context *context,
                                 UT_array *cmd_arr);

/**
 * @brief Processes the DECRYPT_BLOB command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_decrypt_blob_cmd(int sock, struct client_address *client_addr,
                                 struct supervisor_context *context,
                                 UT_array *cmd_arr);

/**
 * @brief Processes the SIGN_BLOB command
 *
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t process_sign_blob_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr);
#endif

/**
 * @brief Get the command function pointer
 *
 * @param cmd The command string
 * @return process_cmd_fn The returned function pointer
 */
process_cmd_fn get_command_function(char *cmd);
#endif
