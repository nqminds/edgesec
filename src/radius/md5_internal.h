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

#ifndef MD5_INTERNAL_H
#define MD5_INTERNAL_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

struct MD5Context {
  uint32_t buf[4];
  uint32_t bits[2];
  uint8_t in[64];
};

#define md5_vector(num_elem, addr, len, mac)                                   \
  edge_md5_vector((num_elem), (addr), (len), (mac))

/**
 * MD5 hash for data vector
 *
 * @param num_elem Number of elements in the data vector
 * @param addr Pointers to the data areas
 * @param len Lengths of the data blocks
 * @param[out] mac Buffer for the hash
 * @retval  0 on success
 * @retval -1 on failure
 *
 * @author Jouni Malinen <j@w1.fi>
 * @date 2009
 * @copyright SPDX-License-Identifier: BSD license
 * @remarks
 * The source of this code was adapted from `md5_internal()` in commit
 * 0a5d68aba50c385e316a30d834d5b6174a4041d2 in `src/crypto/md5-internal.c`
 * of the hostap project, see
 * https://w1.fi/cgit/hostap/tree/src/crypto/md5-internal.c?id=0a5d68aba50c385e316a30d834d5b6174a4041d2#n34
 */
int edge_md5_vector(size_t num_elem, const uint8_t *addr[], const size_t *len,
                    uint8_t *mac);

void MD5Final(unsigned char digest[16], struct MD5Context *context);

#endif /* MD5_INTERNAL_H */
