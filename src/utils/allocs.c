/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the allocs functionalities.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "allocs.h"

void *os_zalloc(size_t size) { return os_calloc(size, 1); }

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
