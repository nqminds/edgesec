/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the identity functions.
 */

#ifndef IDENTITY_H
#define IDENTITY_H

#include "../ap/ap_config.h"
#include "../utils/net.h"

enum IDENTITY_ACCESS {
  IDENTITY_ACCESS_DENY = 0,
  IDENTITY_ACCESS_ALLOW
};

enum IDENTITY_TYPE {
  IDENTITY_TYPE_UNKNOWN = 0,
  IDENTITY_TYPE_MAC,
  IDENTITY_TYPE_CERT
};

struct identity_info {
  uint8_t *cert_id;     /**< The certificate serial number or ID */
  ssize_t cert_id_len; /**< The certificate ID length */
  uint8_t mac_addr[ETHER_ADDR_LEN]; /**< MAC address in byte format */
  int vlanid;
  uint8_t id_pass[AP_SECRET_LEN]; /**< WiFi password assigned to the identity */
  ssize_t id_pass_len; /**< WiFi password length assigned to the identity */
  enum IDENTITY_ACCESS access;           /**< The identity access */
  enum IDENTITY_TYPE type;              /**< The identity type */
};

/**
 * @brief Returns the identity type
 *
 * @param identity The identity array
 * @param identity_len The identity array size
 * @param iinfo The returned identity info
 * @return 0 for success, -1 for error
 */
int process_identity_type(const uint8_t *identity, size_t identity_len, struct identity_info *iinfo);

/**
 * @brief Frees the identity info structure
 *
 * @param iinfo The identity info structure
 */
void free_identity_info(struct identity_info *iinfo);
#endif
