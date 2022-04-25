/*
 * Dynamic data buffer
 * Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * @file wpabuf.c
 * @author Jouni Malinen
 * @brief Dynamic data buffer.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "wpabuf.h"

#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"

static void wpabuf_overflow(const struct wpabuf *buf, size_t len) {
  log_trace("wpabuf %p (size=%lu used=%lu) overflow len=%lu", buf,
            (unsigned long)buf->size, (unsigned long)buf->used,
            (unsigned long)len);
  log_trace("wpabuf overflow");
  abort();
}

int wpabuf_resize(struct wpabuf **_buf, size_t add_len) {
  struct wpabuf *buf = *_buf;

  if (buf == NULL) {
    *_buf = wpabuf_alloc(add_len);
    return *_buf == NULL ? -1 : 0;
  }

  if (buf->used + add_len > buf->size) {
    unsigned char *nbuf;
    if (buf->flags & WPABUF_FLAG_EXT_DATA) {
      nbuf = os_realloc(buf->buf, buf->used + add_len);
      if (nbuf == NULL)
        return -1;
      os_memset(nbuf + buf->used, 0, add_len);
      buf->buf = nbuf;
    } else {
      nbuf = os_realloc(buf, sizeof(struct wpabuf) + buf->used + add_len);
      if (nbuf == NULL)
        return -1;
      buf = (struct wpabuf *)nbuf;
      os_memset(nbuf + sizeof(struct wpabuf) + buf->used, 0, add_len);
      buf->buf = (uint8_t *)(buf + 1);
      *_buf = buf;
    }
    buf->size = buf->used + add_len;
  }

  return 0;
}

/**
 * wpabuf_alloc - Allocate a wpabuf of the given size
 * @len: Length for the allocated buffer
 * Returns: Buffer to the allocated wpabuf or %NULL on failure
 */
struct wpabuf *wpabuf_alloc(size_t len) {
  struct wpabuf *buf = os_zalloc(sizeof(struct wpabuf) + len);
  if (buf == NULL)
    return NULL;

  buf->size = len;
  buf->buf = (uint8_t *)(buf + 1);
  return buf;
}

struct wpabuf *wpabuf_alloc_ext_data(uint8_t *data, size_t len) {
  struct wpabuf *buf = os_zalloc(sizeof(struct wpabuf));
  if (buf == NULL)
    return NULL;

  buf->size = len;
  buf->used = len;
  buf->buf = data;
  buf->flags |= WPABUF_FLAG_EXT_DATA;

  return buf;
}

struct wpabuf *wpabuf_alloc_copy(const void *data, size_t len) {
  struct wpabuf *buf = wpabuf_alloc(len);
  if (buf)
    wpabuf_put_data(buf, data, len);
  return buf;
}

struct wpabuf *wpabuf_dup(const struct wpabuf *src) {
  struct wpabuf *buf = wpabuf_alloc(wpabuf_len(src));
  if (buf)
    wpabuf_put_data(buf, wpabuf_head(src), wpabuf_len(src));
  return buf;
}

/**
 * wpabuf_free - Free a wpabuf
 * @buf: wpabuf buffer
 */
void wpabuf_free(struct wpabuf *buf) {
  if (buf == NULL)
    return;
  if (buf->flags & WPABUF_FLAG_EXT_DATA)
    os_free(buf->buf);
  os_free(buf);
}

void wpabuf_clear_free(struct wpabuf *buf) {
  if (buf) {
    os_memset(wpabuf_mhead(buf), 0, wpabuf_len(buf));
    wpabuf_free(buf);
  }
}

void *wpabuf_put(struct wpabuf *buf, size_t len) {
  void *tmp = wpabuf_mhead_u8(buf) + wpabuf_len(buf);
  buf->used += len;
  if (buf->used > buf->size) {
    wpabuf_overflow(buf, len);
  }
  return tmp;
}

/**
 * wpabuf_concat - Concatenate two buffers into a newly allocated one
 * @a: First buffer
 * @b: Second buffer
 * Returns: wpabuf with concatenated a + b data or %NULL on failure
 *
 * Both buffers a and b will be freed regardless of the return value. Input
 * buffers can be %NULL which is interpreted as an empty buffer.
 */
struct wpabuf *wpabuf_concat(struct wpabuf *a, struct wpabuf *b) {
  struct wpabuf *n = NULL;
  size_t len = 0;

  if (b == NULL)
    return a;

  if (a)
    len += wpabuf_len(a);
  len += wpabuf_len(b);

  n = wpabuf_alloc(len);
  if (n) {
    if (a)
      wpabuf_put_buf(n, a);
    wpabuf_put_buf(n, b);
  }

  wpabuf_free(a);
  wpabuf_free(b);

  return n;
}

/**
 * wpabuf_zeropad - Pad buffer with 0x00 octets (prefix) to specified length
 * @buf: Buffer to be padded
 * @len: Length for the padded buffer
 * Returns: wpabuf padded to len octets or %NULL on failure
 *
 * If buf is longer than len octets or of same size, it will be returned as-is.
 * Otherwise a new buffer is allocated and prefixed with 0x00 octets followed
 * by the source data. The source buffer will be freed on error, i.e., caller
 * will only be responsible on freeing the returned buffer. If buf is %NULL,
 * %NULL will be returned.
 */
struct wpabuf *wpabuf_zeropad(struct wpabuf *buf, size_t len) {
  struct wpabuf *ret;
  size_t blen;

  if (buf == NULL)
    return NULL;

  blen = wpabuf_len(buf);
  if (blen >= len)
    return buf;

  ret = wpabuf_alloc(len);
  if (ret) {
    os_memset(wpabuf_put(ret, len - blen), 0, len - blen);
    wpabuf_put_buf(ret, buf);
  }
  wpabuf_free(buf);

  return ret;
}

void wpabuf_printf(struct wpabuf *buf, char *fmt, ...) {
  va_list ap;
  void *tmp = wpabuf_mhead_u8(buf) + wpabuf_len(buf);
  int res;

  va_start(ap, fmt);
  res = vsnprintf(tmp, buf->size - buf->used, fmt, ap);
  va_end(ap);
  if (res < 0 || (size_t)res >= buf->size - buf->used)
    wpabuf_overflow(buf, res);
  buf->used += res;
}

/**
 * wpabuf_parse_bin - Parse a null terminated string of binary data to a wpabuf
 * @buf: Buffer with null terminated string (hexdump) of binary data
 * Returns: wpabuf or %NULL on failure
 *
 * The string len must be a multiple of two and contain only hexadecimal digits.
 */
struct wpabuf *wpabuf_parse_bin(const char *buf) {
  size_t len;
  struct wpabuf *ret;

  len = strlen(buf);
  if (len & 0x01)
    return NULL;
  len /= 2;

  ret = wpabuf_alloc(len);
  if (ret == NULL)
    return NULL;

  if (hexstr2bin(buf, wpabuf_put(ret, len), len)) {
    wpabuf_free(ret);
    return NULL;
  }

  return ret;
}
