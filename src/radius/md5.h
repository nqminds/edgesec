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

/**
 * HMAC-MD5 over data buffer (RFC 2104)
 *
 * @param key Key for HMAC operations
 * @param key_len Length of the key in bytes
 * @param data Pointers to the data area
 * @param data_len Length of the data area
 * @param[out] mac Buffer for the hash (16 bytes)
 * @retval  0 on success
 * @retval -1 on failure
 *
 * @author Jouni Malinen <j@w1.fi>
 * @date 2003-2009
 * @copyright SPDX-License-Identifier: BSD license
 * @remarks
 * The source of this code was adapted from `hmac_md5()` in commit
 * 0a5d68aba50c385e316a30d834d5b6174a4041d2 in `src/crypto/md5.c`
 * of the hostap project, see
 * https://w1.fi/cgit/hostap/tree/src/crypto/md5.c?id=0a5d68aba50c385e316a30d834d5b6174a4041d2#n98
 */
int edge_hmac_md5(const uint8_t *key, size_t key_len, const uint8_t *data,
                  size_t data_len, uint8_t *mac);

#endif /* MD5_H */
