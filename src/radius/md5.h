/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 * SPDX-License-Identifier: BSD license
 * @version hostapd-2.10
 * @brief MD5 hash implementation and interface functions.
 */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#define MD5_MAC_LEN 16

#define hmac_md5(key, key_len, data, data_len, mac)                            \
  edge_hmac_md5((key), (key_len), (data), (data_len), (mac))

int edge_hmac_md5(const uint8_t *key, size_t key_len, const uint8_t *data,
                  size_t data_len, uint8_t *mac);

#endif /* MD5_H */
