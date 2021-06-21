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
 * @file crypt_config.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of crypt configuration structure.
 */
#ifndef CRYPT_CONFIG_H
#define CRYPT_CONFIG_H

#include <sqlite3.h>

#include "../utils/cryptou.h"

#define MAX_KEY_ID_SIZE 255

/**
 * @brief crypt context structure definition
 * 
 */
struct crypt_context {
  sqlite3 *crypt_db;                             /**< The crypt sqlite db structure. */
  char key_id[MAX_KEY_ID_SIZE];                  /**< The crypt secrets key id. */
  uint8_t crypto_key[AES_KEY_SIZE];              /**< The crypt master key array (Need to be store securely or retrived from the secure memory). */
};

#endif