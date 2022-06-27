/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the bridge creation functions.
 */

#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/log.h"
#include "utils/list.h"
#include "utils/utarray.h"

#include "bridge_list.h"

static const UT_icd tuple_list_icd = {sizeof(struct bridge_mac_tuple), NULL,
                                      NULL, NULL};
static const UT_icd mac_list_icd = {sizeof(uint8_t) * ETH_ALEN, NULL, NULL,
                                    NULL};

struct bridge_mac_list *init_bridge_list(void) {
  struct bridge_mac_list *e;

  e = os_zalloc(sizeof(*e));

  if (e == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  dl_list_init(&e->list);

  return e;
}

void bridge_mac_list_free(struct bridge_mac_list *e) {
  if (e != NULL) {
    dl_list_del(&e->list);
    os_free(e);
  }
}

void free_bridge_list(struct bridge_mac_list *ml) {
  struct bridge_mac_list *e;

  if (ml == NULL)
    return;

  struct dl_list *list = &ml->list;

  while ((e = dl_list_first(list, struct bridge_mac_list, list)))
    bridge_mac_list_free(e);

  bridge_mac_list_free(ml);
}

bool compare_edge(struct bridge_mac_list *e, const uint8_t *mac_addr_left,
                  const uint8_t *mac_addr_right) {
  if (memcmp(e->mac_tuple.src_addr, mac_addr_left, ETH_ALEN) == 0 &&
      memcmp(e->mac_tuple.dst_addr, mac_addr_right, ETH_ALEN) == 0) {
    return true;
  }

  return false;
}

struct bridge_mac_list_tuple get_bridge_mac(struct bridge_mac_list *ml,
                                            const uint8_t *mac_addr_left,
                                            const uint8_t *mac_addr_right) {
  struct bridge_mac_list_tuple ret = {.left_edge = NULL, .right_edge = NULL};
  struct bridge_mac_list *e;

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

  struct dl_list *list = &ml->list;
  dl_list_for_each(e, list, struct bridge_mac_list, list) {
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
  struct bridge_mac_list *src_el, *dst_el;

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

  if (memcmp(mac_addr_left, mac_addr_right, ETH_ALEN) == 0) {
    log_trace("Similar MAC addresses as params");
    return -1;
  }

  struct bridge_mac_list_tuple ret =
      get_bridge_mac(ml, mac_addr_left, mac_addr_right);
  // Existing edge
  if (ret.left_edge && ret.right_edge)
    return 0;

  src_el = os_zalloc(sizeof(*src_el));
  if (src_el == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  dst_el = os_zalloc(sizeof(*dst_el));
  if (dst_el == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  os_memcpy(src_el->mac_tuple.src_addr, mac_addr_left, ETH_ALEN);
  os_memcpy(src_el->mac_tuple.dst_addr, mac_addr_right, ETH_ALEN);
  dl_list_add(&ml->list, &src_el->list);

  os_memcpy(dst_el->mac_tuple.src_addr, mac_addr_right, ETH_ALEN);
  os_memcpy(dst_el->mac_tuple.dst_addr, mac_addr_left, ETH_ALEN);
  dl_list_add(&ml->list, &dst_el->list);

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

  bridge_mac_list_free(e.left_edge);
  bridge_mac_list_free(e.right_edge);

  return 0;
}

int get_src_mac_list(struct bridge_mac_list *ml, const uint8_t *src_addr,
                     UT_array **mac_list_arr) {
  struct bridge_mac_list *e;

  if (ml == NULL) {
    log_trace("ml param is NULL");
    return -1;
  }

  struct dl_list *list = &ml->list;
  utarray_new(*mac_list_arr, &mac_list_icd);
  dl_list_for_each(e, list, struct bridge_mac_list, list) {
    if (memcmp(src_addr, e->mac_tuple.src_addr, ETH_ALEN) == 0) {
      utarray_push_back(*mac_list_arr, e->mac_tuple.dst_addr);
    }
  }

  return utarray_len(*mac_list_arr);
}

int get_all_bridge_edges(struct bridge_mac_list *ml,
                         UT_array **tuple_list_arr) {
  struct bridge_mac_list *e;

  if (ml == NULL) {
    log_trace("ml param is NULL");
    return -1;
  }

  struct dl_list *list = &ml->list;
  utarray_new(*tuple_list_arr, &tuple_list_icd);
  dl_list_for_each(e, list, struct bridge_mac_list, list) {
    utarray_push_back(*tuple_list_arr, &e->mac_tuple);
  }

  return utarray_len(*tuple_list_arr);
}
