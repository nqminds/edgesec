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
 * @file zymkey4_driver.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of zymkey4 driver configuration
 * utilities.
 */
#ifndef ZYMKEY4_DRIVER_H
#define ZYMKEY4_DRIVER_H
#include <sys/types.h>
#include <zymkey/zk_app_utils.h>

/**
 * @brief Initialises an HSM context
 *
 * @return zkCTX* The returned Zymkey4 context, NULL on error
 */
zkCTX *init_zymkey4(void);

/**
 * @brief Closes the zymkey4 context
 *
 * @param ctx The Zymkey4 context
 * @return int 0 on success, -1 on failure
 */
int close_zymkey4(zkCTX *ctx);

/**
 * @brief Generate a random Zymkey4 key
 *
 * @param ctx The Zymkey4 context
 * @param key The returned key
 * @param key_size The key size
 * @return int 0 on success, -1 on failure
 */
int generate_zymkey4_key(zkCTX *ctx, uint8_t *key, size_t key_size);

/**
 * @brief Encrypt a byte array wiht the Zymkey4 HSM
 *
 * @param ctx The Zymkey4 context
 * @param in The input array
 * @param in_size The input array size
 * @param out The output encrypted array
 * @param out_size The output array size
 * @return int 0 on success, -1 on failure
 */
int encrypt_zymkey4_blob(zkCTX *ctx, uint8_t *in, size_t in_size, uint8_t **out,
                         size_t *out_size);

/**
 * @brief Decrypt a byte array wiht the Zymkey4 HSM
 *
 * @param ctx The Zymkey4 context
 * @param in The input array
 * @param in_size The input array size
 * @param out The output decrypted array
 * @param out_size The output array size
 * @return int 0 on success, -1 on failure
 */
int decrypt_zymkey4_blob(zkCTX *ctx, uint8_t *in, size_t in_size, uint8_t **out,
                         size_t *out_size);
#endif
