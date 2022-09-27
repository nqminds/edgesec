/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the hashmap utilities.
 */

#include <stdlib.h>

#ifdef __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__
// strnlen_s() is available in our <string.h> library
#else
// declare strnlen_s() in terms of POSIX strnlen()
#define _POSIX_C_SOURCE 200809L
#define strnlen_s(_string, _maxlen)                                            \
  ((_string) == NULL ? 0 : strnlen((_string), (_maxlen)))
#endif
#include <string.h>

#include <stdbool.h>

#include "log.h"
#include "hashmap.h"

char *hmap_str_keychar_get(hmap_str_keychar **hmap, char *keyptr) {
  hmap_str_keychar *s;

  if (keyptr == NULL) {
    log_trace("keyptr is NULL");
    return NULL;
  }

  HASH_FIND_STR(*hmap, keyptr, s);

  if (s != NULL)
    return s->value;

  return NULL;
}

bool hmap_str_keychar_put(hmap_str_keychar **hmap, char *keyptr, char *value) {
  if (keyptr == NULL) {
    log_trace("keyptr is NULL");
    return false;
  }

  if (value == NULL) {
    log_trace("value is NULL");
    return false;
  }

  if (strnlen_s(keyptr, HASH_KEY_CHAR_SIZE) > HASH_KEY_CHAR_SIZE - 1) {
    log_trace("strlen(keyptr) is greater than key char size");
    return false;
  }

  hmap_str_keychar *s;
  HASH_FIND_STR(*hmap, keyptr, s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_str_keychar *)malloc(sizeof(hmap_str_keychar));
    if (s == NULL) {
      log_errno("malloc");
      return false;
    }

    // Copy the key
    strcpy(s->key, keyptr);
    s->value = strdup(value);
    if (s->value == NULL) {
      log_errno("Failed to strdup(): %s", value);
    }

    HASH_ADD_STR(*hmap, key, s);
  } else {
    // Copy the value
    free(s->value);
    s->value = strdup(value);
    if (s->value == NULL) {
      log_errno("Failed to strdup(): %s", value);
    }
  }

  return true;
}

void hmap_str_keychar_free(hmap_str_keychar **hmap) {
  hmap_str_keychar *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current); /* delete it (users advances to next) */
    free(current->value);     /* free the value content */
    free(current);            /* free it */
  }
}
