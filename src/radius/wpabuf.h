/**
 * @brief Dynamic data buffer.
 * @file wpabuf.h
 * @author Jouni Malinen
 * @author Alois Klink
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: BSD-3-clause
 */

#ifndef WPABUF_H
#define WPABUF_H

#ifdef __FreeBSD__ // FreeBSD
#include <sys/endian.h>
#else // Linux
#include <byteswap.h>
#include <endian.h>
#endif

#include "utils/allocs.h"
#include "utils/log.h"
#include "utils/os.h"

#ifndef WPA_BYTE_SWAP_DEFINED

#define le_to_host16(n) le16toh(n)
#define host_to_le16(n) htole16(n)
#define be_to_host16(n) be16toh(n)
#define host_to_be16(n) htobe16(n)
#define le_to_host32(n) le32toh(n)
#define host_to_le32(n) htole32(n)
#define be_to_host32(n) be32toh(n)
#define host_to_be32(n) htobe32(n)
#define le_to_host64(n) le64toh(n)
#define host_to_le64(n) htole64(n)
#define be_to_host64(n) be64toh(n)
#define host_to_be64(n) htobe64(n)

#define WPA_BYTE_SWAP_DEFINED
#endif /* !WPA_BYTE_SWAP_DEFINED */

/* wpabuf::buf is a pointer to external data */
#define WPABUF_FLAG_EXT_DATA BIT(0)

/* Macros for handling unaligned memory accesses */

static inline uint16_t WPA_GET_BE16(const uint8_t *a) {
  return (a[0] << 8) | a[1];
}

static inline void WPA_PUT_BE16(uint8_t *a, uint16_t val) {
  a[0] = val >> 8;
  a[1] = val & 0xff;
}

static inline uint16_t WPA_GET_LE16(const uint8_t *a) {
  return (a[1] << 8) | a[0];
}

static inline void WPA_PUT_LE16(uint8_t *a, uint16_t val) {
  a[1] = val >> 8;
  a[0] = val & 0xff;
}

static inline uint32_t WPA_GET_BE24(const uint8_t *a) {
  return (a[0] << 16) | (a[1] << 8) | a[2];
}

static inline void WPA_PUT_BE24(uint8_t *a, uint32_t val) {
  a[0] = (val >> 16) & 0xff;
  a[1] = (val >> 8) & 0xff;
  a[2] = val & 0xff;
}

static inline uint32_t WPA_GET_BE32(const uint8_t *a) {
  return ((uint32_t)a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void WPA_PUT_BE32(uint8_t *a, uint32_t val) {
  a[0] = (val >> 24) & 0xff;
  a[1] = (val >> 16) & 0xff;
  a[2] = (val >> 8) & 0xff;
  a[3] = val & 0xff;
}

static inline uint32_t WPA_GET_LE32(const uint8_t *a) {
  return ((uint32_t)a[3] << 24) | (a[2] << 16) | (a[1] << 8) | a[0];
}

static inline void WPA_PUT_LE32(uint8_t *a, uint32_t val) {
  a[3] = (val >> 24) & 0xff;
  a[2] = (val >> 16) & 0xff;
  a[1] = (val >> 8) & 0xff;
  a[0] = val & 0xff;
}

static inline uint64_t WPA_GET_BE64(const uint8_t *a) {
  return (((uint64_t)a[0]) << 56) | (((uint64_t)a[1]) << 48) |
         (((uint64_t)a[2]) << 40) | (((uint64_t)a[3]) << 32) |
         (((uint64_t)a[4]) << 24) | (((uint64_t)a[5]) << 16) |
         (((uint64_t)a[6]) << 8) | ((uint64_t)a[7]);
}

static inline void WPA_PUT_BE64(uint8_t *a, uint64_t val) {
  a[0] = val >> 56;
  a[1] = val >> 48;
  a[2] = val >> 40;
  a[3] = val >> 32;
  a[4] = val >> 24;
  a[5] = val >> 16;
  a[6] = val >> 8;
  a[7] = val & 0xff;
}

static inline uint64_t WPA_GET_LE64(const uint8_t *a) {
  return (((uint64_t)a[7]) << 56) | (((uint64_t)a[6]) << 48) |
         (((uint64_t)a[5]) << 40) | (((uint64_t)a[4]) << 32) |
         (((uint64_t)a[3]) << 24) | (((uint64_t)a[2]) << 16) |
         (((uint64_t)a[1]) << 8) | ((uint64_t)a[0]);
}

static inline void WPA_PUT_LE64(uint8_t *a, uint64_t val) {
  a[7] = val >> 56;
  a[6] = val >> 48;
  a[5] = val >> 40;
  a[4] = val >> 32;
  a[3] = val >> 24;
  a[2] = val >> 16;
  a[1] = val >> 8;
  a[0] = val & 0xff;
}

/*
 * Internal data structure for wpabuf. Please do not touch this directly from
 * elsewhere. This is only defined in header file to allow inline functions
 * from this file to access data.
 */
struct wpabuf {
  size_t size;  /* total size of the allocated buffer */
  size_t used;  /* length of data in the buffer */
  uint8_t *buf; /* pointer to the head of the buffer */
  unsigned int flags;
  /* optionally followed by the allocated buffer */
};

int wpabuf_resize(struct wpabuf **buf, size_t add_len);
struct wpabuf *wpabuf_alloc(size_t len);
struct wpabuf *wpabuf_alloc_ext_data(uint8_t *data, size_t len);
struct wpabuf *wpabuf_alloc_copy(const void *data, size_t len);
struct wpabuf *wpabuf_dup(const struct wpabuf *src);
void wpabuf_free(struct wpabuf *buf);
void wpabuf_clear_free(struct wpabuf *buf);
void *wpabuf_put(struct wpabuf *buf, size_t len);
struct wpabuf *wpabuf_concat(struct wpabuf *a, struct wpabuf *b);
struct wpabuf *wpabuf_zeropad(struct wpabuf *buf, size_t len);
void wpabuf_printf(struct wpabuf *buf, char *fmt, ...) PRINTF_FORMAT(2, 3);
struct wpabuf *wpabuf_parse_bin(const char *buf);

/**
 * wpabuf_size - Get the currently allocated size of a wpabuf buffer
 * @buf: wpabuf buffer
 * Returns: Currently allocated size of the buffer
 */
static inline size_t wpabuf_size(const struct wpabuf *buf) { return buf->size; }

/**
 * wpabuf_len - Get the current length of a wpabuf buffer data
 * @buf: wpabuf buffer
 * Returns: Currently used length of the buffer
 */
static inline size_t wpabuf_len(const struct wpabuf *buf) { return buf->used; }

/**
 * wpabuf_tailroom - Get size of available tail room in the end of the buffer
 * @buf: wpabuf buffer
 * Returns: Tail room (in bytes) of available space in the end of the buffer
 */
static inline size_t wpabuf_tailroom(const struct wpabuf *buf) {
  return buf->size - buf->used;
}

/**
 * wpabuf_head - Get pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline const void *wpabuf_head(const struct wpabuf *buf) {
  return buf->buf;
}

static inline const uint8_t *wpabuf_head_u8(const struct wpabuf *buf) {
  return (const uint8_t *)wpabuf_head(buf);
}

/**
 * wpabuf_mhead - Get modifiable pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline void *wpabuf_mhead(struct wpabuf *buf) { return buf->buf; }

static inline uint8_t *wpabuf_mhead_u8(struct wpabuf *buf) {
  return (uint8_t *)wpabuf_mhead(buf);
}

static inline void wpabuf_put_u8(struct wpabuf *buf, uint8_t data) {
  uint8_t *pos = (uint8_t *)wpabuf_put(buf, 1);
  *pos = data;
}

static inline void wpabuf_put_le16(struct wpabuf *buf, uint16_t data) {
  uint8_t *pos = (uint8_t *)wpabuf_put(buf, 2);
  WPA_PUT_LE16(pos, data);
}

static inline void wpabuf_put_le32(struct wpabuf *buf, uint32_t data) {
  uint8_t *pos = (uint8_t *)wpabuf_put(buf, 4);
  WPA_PUT_LE32(pos, data);
}

static inline void wpabuf_put_be16(struct wpabuf *buf, uint16_t data) {
  uint8_t *pos = (uint8_t *)wpabuf_put(buf, 2);
  WPA_PUT_BE16(pos, data);
}

static inline void wpabuf_put_be24(struct wpabuf *buf, uint32_t data) {
  uint8_t *pos = (uint8_t *)wpabuf_put(buf, 3);
  WPA_PUT_BE24(pos, data);
}

static inline void wpabuf_put_be32(struct wpabuf *buf, uint32_t data) {
  uint8_t *pos = (uint8_t *)wpabuf_put(buf, 4);
  WPA_PUT_BE32(pos, data);
}

static inline void wpabuf_put_data(struct wpabuf *buf, const void *data,
                                   size_t len) {
  if (data)
    os_memcpy(wpabuf_put(buf, len), data, len);
}

static inline void wpabuf_put_buf(struct wpabuf *dst,
                                  const struct wpabuf *src) {
  wpabuf_put_data(dst, wpabuf_head(src), wpabuf_len(src));
}

static inline void wpabuf_set(struct wpabuf *buf, const void *data,
                              size_t len) {
  buf->buf = (uint8_t *)data;
  buf->flags = WPABUF_FLAG_EXT_DATA;
  buf->size = buf->used = len;
}

static inline void wpabuf_put_str(struct wpabuf *dst, const char *str) {
  wpabuf_put_data(dst, str, strlen(str));
}

#endif /* WPABUF_H */
