/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the allocs functionalities.
 */

#include <stddef.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include "allocs.h"

void *os_zalloc(size_t size) {
  void *n = os_malloc(size);
  if (n != NULL)
    os_memset(n, 0, size);
  return n;
}

void *os_memdup(const void *src, size_t len) {
  void *r = os_malloc(len);

  if (r && src)
    os_memcpy(r, src, len);
  return r;
}

char *os_strdup(const char *s) {
  char *dest = NULL;
  size_t len = strlen(s) + 1;

  if (s != NULL) {
    dest = (char *)os_malloc(len);
    if (dest == NULL) {
      return NULL;
    }

    strcpy(dest, s);
  }

  return dest;
}
