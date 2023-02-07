/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 * SPDX-License-Identifier: BSD licence
 * @version hostapd-2.10
 * @brief File containing the common definitions used by radius and eap
 */

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

#include "utils/allocs.h"
#include "utils/log.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

/*
 * Definitions for sparse validation
 * (http://kernel.org/pub/linux/kernel/people/josh/sparse/)
 */
#ifdef __CHECKER__
#define __force __attribute__((force))
#undef __bitwise
#define __bitwise __attribute__((bitwise))
#else
#define __force
#undef __bitwise
#define __bitwise
#endif

typedef u16 __bitwise be16;
typedef u16 __bitwise le16;
typedef u32 __bitwise be32;
typedef u32 __bitwise le32;
typedef u64 __bitwise be64;
typedef u64 __bitwise le64;

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

#ifndef bswap_16
#define bswap_16(a) ((((u16)(a) << 8) & 0xff00) | (((u16)(a) >> 8) & 0xff))
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le_to_host16(n) ((__force u16)(le16)(n))
#define host_to_le16(n) ((__force le16)(u16)(n))
#define be_to_host16(n) bswap_16((__force u16)(be16)(n))
#define host_to_be16(n) ((__force be16)bswap_16((n)))
#define le_to_host32(n) ((__force u32)(le32)(n))
#define host_to_le32(n) ((__force le32)(u32)(n))
#define be_to_host32(n) bswap_32((__force u32)(be32)(n))
#define host_to_be32(n) ((__force be32)bswap_32((n)))
#define le_to_host64(n) ((__force u64)(le64)(n))
#define host_to_le64(n) ((__force le64)(u64)(n))
#define be_to_host64(n) bswap_64((__force u64)(be64)(n))
#define host_to_be64(n) ((__force be64)bswap_64((n)))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le_to_host16(n) bswap_16(n)
#define host_to_le16(n) bswap_16(n)
#define be_to_host16(n) (n)
#define host_to_be16(n) (n)
#define le_to_host32(n) bswap_32(n)
#define host_to_le32(n) bswap_32(n)
#define be_to_host32(n) (n)
#define host_to_be32(n) (n)
#define le_to_host64(n) bswap_64(n)
#define host_to_le64(n) bswap_64(n)
#define be_to_host64(n) (n)
#define host_to_be64(n) (n)
#ifndef WORDS_BIGENDIAN
#define WORDS_BIGENDIAN
#endif
#else
#error Could not determine CPU byte order
#endif

static inline void WPA_PUT_LE16(u8 *a, u16 val) {
  a[1] = val >> 8;
  a[0] = val & 0xff;
}

static inline void WPA_PUT_LE32(u8 *a, u32 val) {
  a[3] = (val >> 24) & 0xff;
  a[2] = (val >> 16) & 0xff;
  a[1] = (val >> 8) & 0xff;
  a[0] = val & 0xff;
}

static inline void WPA_PUT_LE64(u8 *a, u64 val) {
  a[7] = val >> 56;
  a[6] = val >> 48;
  a[5] = val >> 40;
  a[4] = val >> 32;
  a[3] = val >> 24;
  a[2] = val >> 16;
  a[1] = val >> 8;
  a[0] = val & 0xff;
}

static inline void WPA_PUT_BE16(u8 *a, u16 val) {
  a[0] = val >> 8;
  a[1] = val & 0xff;
}

static inline void WPA_PUT_BE24(u8 *a, u32 val) {
  a[0] = (val >> 16) & 0xff;
  a[1] = (val >> 8) & 0xff;
  a[2] = val & 0xff;
}

static inline void WPA_PUT_BE32(u8 *a, u32 val) {
  a[0] = (val >> 24) & 0xff;
  a[1] = (val >> 16) & 0xff;
  a[2] = (val >> 8) & 0xff;
  a[3] = val & 0xff;
}

static inline void WPA_PUT_BE64(u8 *a, u64 val) {
  a[0] = val >> 56;
  a[1] = val >> 48;
  a[2] = val >> 40;
  a[3] = val >> 32;
  a[4] = val >> 24;
  a[5] = val >> 16;
  a[6] = val >> 8;
  a[7] = val & 0xff;
}

static inline u32 WPA_GET_BE32(const u8 *a) {
  return ((u32)a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline u32 WPA_GET_BE24(const u8 *a) {
  return (a[0] << 16) | (a[1] << 8) | a[2];
}

/**
 * @brief Allocate duplicate of passed memory chunk
 *
 * This function allocates a memory block like os_malloc() would, and
 * copies the given source buffer into it.
 *
 * @param src Source buffer to duplicate
 * @param len Length of source buffer
 * @return `NULL` if allocation failed, copy of src buffer otherwise
 *
 * @author Johannes Berg <johannes.berg@intel.com>
 * @date 2017-03-17
 * @copyright SPDX-License-Identifier: BSD license
 * @remark Adapted from hostap commit dbdda355d0add3f7d96e3279321d3a63abfc4b32,
 * see
 * https://w1.fi/cgit/hostap/commit/?id=dbdda355d0add3f7d96e3279321d3a63abfc4b32
 */
static inline void *os_memdup(const void *src, size_t len) {
  void *r = os_malloc(len);

  if (r && src)
    os_memcpy(r, src, len);
  return r;
}

#define wpa_printf(level, ...)                                                 \
  log_levels(LOGC_TRACE, __FILENAME__, __LINE__, __VA_ARGS__)
#define wpa_snprintf_hex(buf, buf_size, data, len)                             \
  printf_hex(buf, buf_size, data, len, 0)

static inline void printf_encode(char *txt, size_t maxlen, const uint8_t *data,
                                 size_t len) {
  char *end = txt + maxlen;
  size_t i;

  for (i = 0; i < len; i++) {
    if (txt + 4 >= end)
      break;

    switch (data[i]) {
      case '\"':
        *txt++ = '\\';
        *txt++ = '\"';
        break;
      case '\\':
        *txt++ = '\\';
        *txt++ = '\\';
        break;
      case '\033':
        *txt++ = '\\';
        *txt++ = 'e';
        break;
      case '\n':
        *txt++ = '\\';
        *txt++ = 'n';
        break;
      case '\r':
        *txt++ = '\\';
        *txt++ = 'r';
        break;
      case '\t':
        *txt++ = '\\';
        *txt++ = 't';
        break;
      default:
        // check if value is a valid printable ASCII char
        // this also confirms that we can safely cast unsigned data to signed
        // char
        if (data[i] >= 32 && data[i] <= 126) {
          *txt++ = (char)data[i];
        } else {
          // guaranteed to be positive and to have 4 chars left, as otherwise
          // loop will break
          size_t max_chars_to_print = (size_t)(end - txt);
          txt += snprintf(txt, max_chars_to_print, "\\x%02x", data[i]);
        }
        break;
    }
  }

  *txt = '\0';
}

#ifndef wpa_trace_show
#define wpa_trace_show(s) log_trace("%s", s)
#endif

#define TEST_FAIL() 0
#endif
