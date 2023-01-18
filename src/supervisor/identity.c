/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the identity functions.
 */

#include "identity.h"

int convert_identity2mac(const uint8_t *identity, size_t identity_len, uint8_t *mac_addr) {
  char *mac_addr_str = sys_zalloc(identity_len + 1);
  if (mac_addr_str == NULL) {
    log_errno("sys_zalloc");
    return -1;
  }

  sprintf(mac_addr_str, "%.*s", (int)identity_len, identity);

  if (convert_ascii2mac(mac_addr_str, mac_addr) < 0) {
    log_error("convert_ascii2mac fail");
    os_free(mac_addr_str);
    return -1;
  }
  os_free(mac_addr_str);

  return 0;
}

int process_identity_type(const uint8_t *identity, size_t identity_len, struct identity_info *iinfo) {
  if (identity == NULL) {
    log_error("identity param is NULL");
    return -1;
  }

  if (iinfo == NULL) {
    log_error("iinfo param is NULL");
    return -1;
  }
  
  if (convert_identity2mac(identity, identity_len, iinfo->mac_addr) < 0) {
    iinfo->type = IDENTITY_TYPE_CERT;
  } else {
    iinfo->type = IDENTITY_TYPE_MAC;
  }

  return 0;
}