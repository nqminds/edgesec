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

#include "utils/log.h"
#include "utils/allocs.h"

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

#ifndef __must_check
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#define __must_check __attribute__((__warn_unused_result__))
#else
#define __must_check
#endif /* __GNUC__ */
#endif /* __must_check */

#ifndef __maybe_unused
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#define __maybe_unused __attribute__((unused))
#else
#define __maybe_unused
#endif /* __GNUC__ */
#endif /* __must_check */

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

static inline int os_snprintf_error(size_t size, int res)
{
	return res < 0 || (unsigned int) res >= size;
}

static inline void bin_clear_free(void *bin, size_t len)
{
	if (bin) {
		os_memset(bin, 0, len); //forced_memzero(bin, len);
		os_free(bin);
	}
}

#define WLAN_REASON_IEEE_802_1X_AUTH_FAILED 23

struct hostapd_radius_attr {
	u8 type;
	struct wpabuf *val;
	struct hostapd_radius_attr *next;
};

/* Debugging function - conditional printf and hex dump. Driver wrappers can
 * use these for debugging purposes. */

enum {
	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
};

#define wpa_printf(level, ...)                                                 \
  log_levels(LOGC_TRACE, __FILENAME__, __LINE__, __VA_ARGS__)
#define wpa_snprintf_hex(buf, buf_size, data, len)                             \
  printf_hex(buf, buf_size, data, len, 0)

static inline void wpa_hexdump_ascii(int level, const char *title, const void *buf,
			       size_t len) {
  (void)level;
  char hex_buf[32];
  printf_hex(hex_buf, 32, buf, len, 0);
  log_trace("%s - hexdump(len=%lu):%s", title, len, hex_buf);
}

#define wpa_hexdump(level, title, buf, len) wpa_hexdump_ascii(level, title, buf, len)

#ifndef wpa_trace_show
#define wpa_trace_show(s) log_trace("%s", s)
#endif

#define TEST_FAIL() 0
#endif
