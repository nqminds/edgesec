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

#define IDENTITY_CERT_PREFIX "cert-"

ssize_t convert_identity2certid(const char *identity, uint8_t **cert_id) {
  ssize_t cert_id_len = -1;

  *cert_id = NULL;

  //cert-2AFE6B8ADBAC8145803605F53B43F8268D9996D1
  char *pos = sys_strstr(identity, IDENTITY_CERT_PREFIX);
  if (pos == NULL) {
    log_error("cert prefix not found");
    return -1;
  }
  char *cert = pos + os_strlen(IDENTITY_CERT_PREFIX);

  size_t cert_str_len = os_strlen(cert);
  if (cert_str_len & 0x01) {
    log_error("Identity length not even");
    return -1;
  }
  cert_id_len = cert_str_len / 2;

  if ((*cert_id = sys_zalloc(cert_id_len)) == NULL) {
    log_errno("sys_zalloc");
    return -1;
  }

  if (convert_hexstr2bin(cert, *cert_id, cert_id_len) < 0) {
    os_free(*cert_id);
    *cert_id = NULL;
    return -1;
  }

  return cert_id_len;
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

  char *identity_str = sys_zalloc(identity_len + 1);
  if (identity_str == NULL) {
    log_errno("sys_zalloc");
    return -1;
  }

  sprintf(identity_str, "%.*s", (int)identity_len, identity);

  if (convert_ascii2mac(identity_str, iinfo->mac_addr) < 0) {
    if ((iinfo->cert_id_len = convert_identity2certid(identity_str, &iinfo->cert_id)) < 0) {
      log_error("convert_identity2certid fail");
      os_free(identity_str);
      return -1;    
    }

    iinfo->type = IDENTITY_TYPE_CERT;
  } else {
    iinfo->type = IDENTITY_TYPE_MAC;
  }

  os_free(identity_str);
  return 0;
}

void free_identity_info(struct identity_info *iinfo) {
  if (iinfo != NULL) {
    if (iinfo->cert_id != NULL) {
      os_free(iinfo->cert_id);
    }
    os_free(iinfo);
  }
}