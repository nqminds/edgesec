/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the radius config.
 */

#ifndef RADIUS_CONFIG_H
#define RADIUS_CONFIG_H

#include "../utils/net.h"
#include "../supervisor/identity.h"
#include "attr_mapper.h"

#define RADIUS_SECRET_LEN 255

/**
 * @brief Radius configuration structure
 *
 */
struct radius_conf {
  char client_conf_path[MAX_OS_PATH_LEN];  /**< The client config path string */
  char eap_ca_cert_path[MAX_OS_PATH_LEN];  /**< The certificate authority file path in pem format */
  char eap_server_cert_path[MAX_OS_PATH_LEN]; /**< The server certificate file path in pem format */
  char eap_server_key_path[MAX_OS_PATH_LEN]; /**< The server private key file path */
  char eap_dh_path[MAX_OS_PATH_LEN]; /**< The Diffie-Hellman config params file path */
  int radius_port;                           /**< Radius port */
  char radius_client_ip[OS_INET_ADDRSTRLEN]; /**< Radius client IP string */
  int radius_client_mask; /**< Radius client IP mask string */
  char radius_server_ip[OS_INET_ADDRSTRLEN]; /**< Radius server IP string */
  int radius_server_mask;                /**< Radius server IP mask string */
  char radius_secret[RADIUS_SECRET_LEN]; /**< Radius secret string */
};

typedef struct identity_info * (*get_identity_ac_cb)(const uint8_t *identity,
                                                size_t identity_len,  
                                                void *ctx_cb);

struct radius_context {
  struct radius_conf *rconf;
  struct radius_server_conf *sconf;
  struct radius_server_data *srv;
  attr_mac_conn *attr_mapper;
  get_identity_ac_cb get_identity_ac_fn;
  void *ctx_cb;
  void *tls_ctx;
};
#endif
