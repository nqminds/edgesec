/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the Radius attributes mapper.
 */

#include <stdbool.h>
#include <inttypes.h>
#include <utarray.h>
#include <uthash.h>

#include "../utils/net.h"
#include "../utils/hashmap.h"
#include "../utils/os.h"

#include "attr_mapper.h"
#include "radius.h"
#include "wpabuf.h"

// Randomlyh selected MAC key for MD5 algorithm
static const uint8_t mac_hash_base_key[MD5_MAC_LEN] = {0x76, 0x7a, 0x20, 0x0b,
                                                       0x20, 0x0c, 0x90, 0x38,
                                                       0xc0, 0xae, 0x91, 0x07,
                                                       0x41, 0xba, 0x47, 0xdb};

void free_attr(struct hostapd_radius_attr *attr) {
  struct hostapd_radius_attr *prev;

  while (attr) {
    prev = attr;
    attr = attr->next;
    wpabuf_free(prev->val);
    os_free(prev);
  }
}

void free_attr_contents(struct hostapd_radius_attr *attr) {
    wpabuf_free(attr->val);
    free_attr(attr->next);
}

void copy_attr_contents(struct hostapd_radius_attr *src, struct hostapd_radius_attr *dst) {
    dst->val = src->val;
    dst->type = src->type;
    dst->next = src->next;
}

int get_attr_mapper(attr_mac_conn **hmap, const uint8_t *key,
                    size_t key_size,
                    struct hostapd_radius_attr **attr) {
  attr_mac_conn *s;

  if (hmap == NULL) {
    log_error("hmap param is NULL");
    return -1;
  }

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

  if (attr == NULL) {
    log_error("attr param is NULL");
    return -1;
  }

  uint8_t hashkey[MD5_MAC_LEN];
  if (hmac_md5_base(mac_hash_base_key, MD5_MAC_LEN, key, key_size, hashkey) < 0) {
    log_error("hmac_md5_base fail");
    return -1;
  }

  HASH_FIND(hh, *hmap, hashkey, MD5_MAC_LEN, s);

  if (s != NULL) {
    *attr = s->attr;
    return 1;
  }

  return 0;
}

int put_attr_mapper(attr_mac_conn **hmap, const uint8_t *key,
                    size_t key_size,
                    struct hostapd_radius_attr *attr) {
  attr_mac_conn *s;

  if (hmap == NULL) {
    log_error("hmap param is NULL");
    return -1;
  }

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

  if (attr == NULL) {
    log_error("attr param is NULL");
    return -1;
  }

  uint8_t hashkey[MD5_MAC_LEN];
  if (hmac_md5_base(mac_hash_base_key, MD5_MAC_LEN, key, key_size, hashkey) < 0) {
    log_error("hmac_md5_base fail");
    return -1;
  }

  HASH_FIND(hh, *hmap, hashkey, MD5_MAC_LEN, s);

  if (s == NULL) {
    s = (attr_mac_conn *)os_malloc(sizeof(attr_mac_conn));
    if (s == NULL) {
      log_errno("os_malloc");
      return -1;
    }

    // Copy the key and value
    os_memcpy(s->key, hashkey, MD5_MAC_LEN);
    s->attr = attr;

    HASH_ADD(hh, *hmap, key[0], MD5_MAC_LEN, s);
  } else {
    // Copy the value
    free_attr_contents(s->attr);
    copy_attr_contents(attr, s->attr);
    // remove the main struct only
    os_free(attr);
  }

  return true;
}

void free_attr_mapper(attr_mac_conn **hmap) {
  attr_mac_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    free_attr(current->attr);
    HASH_DEL(*hmap, current); /* delete it (users advances to next) */
    os_free(current);         /* free it */
  }
}
