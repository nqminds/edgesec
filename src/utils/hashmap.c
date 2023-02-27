/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the hashmap utilities.
 */
// needed for strnlen() and strdup()
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>

#ifdef __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__
// strnlen_s() is available in our <string.h> library
#else
// declare strnlen_s() in terms of POSIX strnlen()
#define strnlen_s(_string, _maxlen)                                            \
  ((_string) == NULL ? 0 : strnlen((_string), (_maxlen)))
#endif
#include <string.h>

#include <stdbool.h>

#include "hashmap.h"
#include "log.h"

const char *hmap_str_keychar_get(const hmap_str_keychar *hmap,
                                 const char *keyptr) {
  if (keyptr == NULL) {
    log_trace("keyptr is NULL");
    return NULL;
  }

  const hmap_str_keychar *s;
  HASH_FIND_STR(hmap, keyptr, s);

  if (s != NULL)
    return s->value;

  return NULL;
}

bool hmap_str_keychar_put(hmap_str_keychar **hmap, const char *keyptr,
                          const char *value) {
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

  hmap_str_keychar *new_entry = malloc(sizeof(hmap_str_keychar));
  if (new_entry == NULL) {
    log_errno("malloc: failed to malloc");
    return false;
  }
  strcpy(new_entry->key, keyptr);
  new_entry->value = strdup(value);
  if (new_entry->value == NULL) {
    log_errno("Failed to strdup(): %s", value);
    free(new_entry);
    return false;
  }

  hmap_str_keychar *old_entry;
  HASH_REPLACE_STR(*hmap, key, new_entry, old_entry);

  if (old_entry != NULL) {
    free(old_entry->value);
    free(old_entry);
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
