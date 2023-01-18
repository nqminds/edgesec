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

int get_identity_type(const uint8_t *identity, size_t identity_len, enum IDENTITY_TYPE *type) {
  (void)identity_len;
  if (identity == NULL) {
    log_error("identity param is NULL");
    return -1;
  }

  if (type == NULL) {
    log_error("type param is NULL");
    return -1;
  }


  return 0;
}