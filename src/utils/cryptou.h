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
 * @file cryptou.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the cryptographic utilities.
 */

#ifndef CRYPTOU_H
#define CRYPTOU_H

#include <stdint.h>

#define SALT_SIZE           16
#define AES_KEY_SIZE        32
#define MAX_KEY_ITERATIONS  1000

/**
 * @brief Transforms a secret buf into a key
 * 
 * @param buf The secret buf
 * @param buf_size The buf size
 * @param salt The salt buf
 * @param salt_size The salt buf size
 * @param key_size The key size
 * @param key The returned key
 * @return int 0 on success, -1 on failure
 */
int crypto_buf2key(uint8_t *buf, int buf_size, uint8_t *salt, int salt_size, int key_size, uint8_t *key);
#endif