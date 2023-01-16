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

int md5_vector_base(size_t num_elem, const uint8_t *addr[], const size_t *len,
               uint8_t *mac);

void MD5Init_base(struct MD5Context *context);
void MD5Update_base(struct MD5Context *context, unsigned char const *buf,
               unsigned len);
void MD5Final_base(unsigned char digest[16], struct MD5Context *context);

#endif /* MD5_INTERNAL_H */
