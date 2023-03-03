/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the bridge creation functions.
 */
#include <utlist.h>

#include "utils/allocs.h"
#include "utils/log.h"
#include "utils/os.h"

#include "bridge_list.h"

static const UT_icd tuple_list_icd = {sizeof(struct bridge_mac_tuple), NULL,
                                      NULL, NULL};
static const UT_icd mac_list_icd = {sizeof(uint8_t) * ETHER_ADDR_LEN, NULL,
                                    NULL, NULL};

struct bridge_mac_list *init_bridge_list(void) {
  return os_zalloc(sizeof(struct bridge_mac_list));
}

static void bridge_mac_list_free(struct bridge_mac_list *ml,
                                 struct bridge_mac_list_entry *entry) {
  if (entry != NULL) {
    CDL_DELETE(ml->head, entry);
    os_free(entry);
  }
}

void free_bridge_list(struct bridge_mac_list *mac_list) {
  struct bridge_mac_list_entry *elt, *tmp1, *tmp2;
  CDL_FOREACH_SAFE(mac_list->head, elt, tmp1, tmp2) {
    CDL_DELETE(mac_list->head, elt);
    os_free(elt);
  }
}

bool compare_edge(struct bridge_mac_list_entry *e, const uint8_t *mac_addr_left,
                  const uint8_t *mac_addr_right) {
  if (memcmp(e->mac_tuple.src_addr, mac_addr_left, ETHER_ADDR_LEN) == 0 &&
      memcmp(e->mac_tuple.dst_addr, mac_addr_right, ETHER_ADDR_LEN) == 0) {
    return true;
  }

  return false;
}

struct bridge_mac_list_tuple get_bridge_mac(struct bridge_mac_list *ml,
                                            const uint8_t *mac_addr_left,
                                            const uint8_t *mac_addr_right) {
  struct bridge_mac_list_tuple ret = {.left_edge = NULL, .right_edge = NULL};

  if (ml == NULL) {
    log_trace("ml param is NULL");
    return ret;
  }

  if (mac_addr_left == NULL) {
    log_trace("mac_addr_left param is NULL");
    return ret;
  }

  if (mac_addr_right == NULL) {
    log_trace("mac_addr_right param is NULL");
    return ret;
  }

  struct bridge_mac_list_entry *e;
  CDL_FOREACH(ml->head, e) {
    if (compare_edge(e, mac_addr_left, mac_addr_right)) {
      ret.left_edge = e;
    }

    if (compare_edge(e, mac_addr_right, mac_addr_left)) {
      ret.right_edge = e;
    }
  }
  return ret;
}

int check_bridge_exist(struct bridge_mac_list *ml, const uint8_t *mac_addr_left,
                       const uint8_t *mac_addr_right) {
  struct bridge_mac_list_tuple ret =
      get_bridge_mac(ml, mac_addr_left, mac_addr_right);

  // Existing edge
  if (ret.left_edge && ret.right_edge)
    return 1;

  return 0;
}

int add_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left,
                   const uint8_t *mac_addr_right) {
  if (ml == NULL) {
    log_trace("ml param is NULL");
    return -1;
  }

  if (mac_addr_left == NULL) {
    log_trace("mac_addr_left param is NULL");
    return -1;
  }

  if (mac_addr_right == NULL) {
    log_trace("mac_addr_right param is NULL");
    return -1;
  }

  if (memcmp(mac_addr_left, mac_addr_right, ETHER_ADDR_LEN) == 0) {
    log_trace("Similar MAC addresses as params");
    return -1;
  }

  struct bridge_mac_list_tuple ret =
      get_bridge_mac(ml, mac_addr_left, mac_addr_right);
  // Existing edge
  if (ret.left_edge && ret.right_edge)
    return 0;

  struct bridge_mac_list_entry *src_el = os_zalloc(sizeof(*src_el));
  if (src_el == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  struct bridge_mac_list_entry *dst_el = os_zalloc(sizeof(*dst_el));
  if (dst_el == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  os_memcpy(src_el->mac_tuple.src_addr, mac_addr_left, ETHER_ADDR_LEN);
  os_memcpy(src_el->mac_tuple.dst_addr, mac_addr_right, ETHER_ADDR_LEN);
  CDL_PREPEND(ml->head, src_el);

  os_memcpy(dst_el->mac_tuple.src_addr, mac_addr_right, ETHER_ADDR_LEN);
  os_memcpy(dst_el->mac_tuple.dst_addr, mac_addr_left, ETHER_ADDR_LEN);
  CDL_PREPEND(ml->head, dst_el);

  return 1;
}

int remove_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left,
                      const uint8_t *mac_addr_right) {
  if (ml == NULL) {
    log_trace("ml param is NULL");
    return -1;
  }

  if (mac_addr_left == NULL) {
    log_trace("mac_addr_left param is NULL");
    return -1;
  }

  if (mac_addr_right == NULL) {
    log_trace("mac_addr_right param is NULL");
    return -1;
  }

  struct bridge_mac_list_tuple e =
      get_bridge_mac(ml, mac_addr_left, mac_addr_right);
  if (e.left_edge == NULL || e.right_edge == NULL) {
    log_trace("Missing edge");
  }

  bridge_mac_list_free(ml, e.left_edge);
  bridge_mac_list_free(ml, e.right_edge);

  return 0;
}

int get_src_mac_list(struct bridge_mac_list *ml, const uint8_t *src_addr,
                     UT_array **mac_list_arr) {
  if (ml == NULL) {
    log_trace("ml param is NULL");
    return -1;
  }

  utarray_new(*mac_list_arr, &mac_list_icd);

  struct bridge_mac_list_entry *e;
  CDL_FOREACH(ml->head, e) {
    if (memcmp(src_addr, e->mac_tuple.src_addr, ETHER_ADDR_LEN) == 0) {
      utarray_push_back(*mac_list_arr, e->mac_tuple.dst_addr);
    }
  }

  return utarray_len(*mac_list_arr);
}

int get_all_bridge_edges(struct bridge_mac_list *ml,
                         UT_array **tuple_list_arr) {

  if (ml == NULL) {
    log_trace("ml param is NULL");
    return -1;
  }

  utarray_new(*tuple_list_arr, &tuple_list_icd);
  struct bridge_mac_list_entry *e;
  CDL_FOREACH(ml->head, e) {
    utarray_push_back(*tuple_list_arr, &e->mac_tuple);
  }

  return utarray_len(*tuple_list_arr);
}
