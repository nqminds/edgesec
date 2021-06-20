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
 * @file cryptou.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the cryptographic utilities.
 */

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "cryptou.h"

#include "../utils/log.h"
#include "../utils/base64.h"

int crypto_buf2key(uint8_t *buf, int buf_size, uint8_t *salt, int salt_size, int key_size, uint8_t *key)
{
  if (PKCS5_PBKDF2_HMAC(buf, buf_size, salt, SALT_SIZE, MAX_KEY_ITERATIONS,
                    EVP_sha256(), key_size, key) < 1) {
    log_trace("PKCS5_PBKDF2_HMAC fail wit code=%d", ERR_get_error());
    return -1;
  }

  return 0;
}