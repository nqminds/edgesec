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

#ifndef __maybe_unused
#if defined __has_attribute
#if __has_attribute(unused)
/**
 * If used before a variable, tells the compiler that variable can be unused.
 * (e.g. does the same thing as casting to `(void)`).
 *
 * @see https://clang.llvm.org/docs/AttributeReference.html#maybe-unused-unused
 */
#define __maybe_unused __attribute__((unused))
#else
#define __maybe_unused
#endif /* __has_attribute(unused) */
#else
#define __maybe_unused
#endif /* defined __has_attribute */
#endif /* __maybe_unused */

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
 * Returns `true` if `snprintf` was truncated.
 *
 * @param size - Size of snprintf() output buffer.
 * @param res - Return code from snprintf()
 * @retval 0 if snprintf() was successful
 * @retval 1 if snprintf() failed
 *
 * @author Jouni Malinen <j@w1.fi>
 * @remarks Taken from commit 0047306bc9ab7d46e8cc22ff9a3e876c47626473 of
 * hostap, see
 * https://w1.fi/cgit/hostap/commit/?id=0047306bc9ab7d46e8cc22ff9a3e876c47626473
 */
static inline int os_snprintf_error(size_t size, int res) {
  return res < 0 || (unsigned int)res >= size;
}

/**
 * Sets the memory to '\0' before freeing it.
 *
 * Clears the given memory to `'\0'` before free()-ing it, to avoid leaking
 * sensitive information.
 *
 * @param bin - Pointer to the memory to free()
 * @param len - Number of bytes to `'\0'` before free()-ing
 * @see
 * https://wiki.sei.cmu.edu/confluence/display/c/MEM03-C.+Clear+sensitive+information+stored+in+reusable+resources
 * @see https://cwe.mitre.org/data/definitions/226.html
 * @remarks Adapted from commit 19c48da06b6980915e97a84ea8387a9db858c662
 * of hostap, see
 * https://w1.fi/cgit/hostap/commit/?id=19c48da06b6980915e97a84ea8387a9db858c662
 */
static inline void bin_clear_free(void *bin, size_t len) {
  if (bin) {
    // may be optimized out by a smart compiler, we should use
    // memset_s (C11 Annex K) or memset_explicit (C23) instead
    os_memset(bin, '\0', len);
    os_free(bin);
  }
}

#define wpa_printf(level, ...)                                                 \
  log_levels(LOGC_TRACE, __FILENAME__, __LINE__, __VA_ARGS__)
#define wpa_snprintf_hex(buf, buf_size, data, len)                             \
  printf_hex(buf, buf_size, data, len, false)

/**
 * Prints the first 32-bytes of the given buffer with the given title.
 *
 * @param level priority level of the message
 * @param title of for the message
 * @param data buffer to be dumped
 * @param length of the buf
 *
 * @remarks Designed to have the same API as hostap's wpa_hexdump_ascii(),
 * see https://w1.fi/cgit/hostap/tree/src/utils/wpa_debug.h?h=hostap_2_10#n118
 * However, it prints every byte as hex, and never prints bytes as ASCII.
 */
static inline void
wpa_hexdump_ascii(__maybe_unused int level, // used by hostap, but our
                                            // implementation doesn't use it
                  const char *title, const void *buf, size_t len) {
  char hex_buf[32];
  printf_hex(hex_buf, 32, buf, len, false);
  log_trace("%s - hexdump(len=%lu):%s", title, len, hex_buf);
}

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
