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

int get_attr_mapper(attr_mac_conn **hmap, uint8_t mac_addr[ETHER_ADDR_LEN],
                   struct hostapd_radius_attr **attr) {
  attr_mac_conn *s;

  if (hmap == NULL) {
    log_trace("hmap param is NULL");
    return -1;
  }

  if (mac_addr == NULL) {
    log_trace("mac_addr param is NULL");
    return -1;
  }

  if (attr == NULL) {
    log_trace("attr param is NULL");
    return -1;
  }

  HASH_FIND(hh, *hmap, mac_addr, ETHER_ADDR_LEN, s);

  if (s != NULL) {
    *attr = s->attr;
    return 1;
  }

  return 0;
}

int put_attr_mapper(attr_mac_conn **hmap, uint8_t mac_addr[ETHER_ADDR_LEN], struct hostapd_radius_attr *attr) {
  attr_mac_conn *s;

  if (hmap == NULL) {
    log_trace("hmap param is NULL");
    return -1;
  }

  if (mac_addr == NULL) {
    log_trace("mac_addr param is NULL");
    return -1;
  }

  if (attr == NULL) {
    log_trace("attr param is NULL");
    return -1;
  }

  HASH_FIND(hh, *hmap, mac_addr, ETHER_ADDR_LEN, s);

  if (s == NULL) {
    s = (attr_mac_conn *)os_malloc(sizeof(attr_mac_conn));
    if (s == NULL) {
      log_errno("os_malloc");
      return -1;
    }

    // Copy the key and value
    os_memcpy(s->key, mac_addr, ETHER_ADDR_LEN);
    s->attr = attr;

    HASH_ADD(hh, *hmap, key[0], ETHER_ADDR_LEN, s);
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
