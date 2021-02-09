/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
 *                                                                          *
 * This file is part of EDGESec.                                            *
 *                                                                          *
 *   EDGESec is free software: you can redistribute it and/or modify it     *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   EDGESec is distributed in the hope that it will be useful,             *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with EDGESec. If not, see <http://www.gnu.org/licenses/>.*
 ****************************************************************************/

/**
 * @file bridge_list.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the bridge creation functions.
 */

#include "utils/os.h"
#include "utils/log.h"
#include "utils/list.h"
#include "utils/utarray.h"

#include "bridge_list.h"

static const UT_icd tuple_list_icd = {sizeof(struct bridge_mac_tuple), NULL, NULL, NULL};

struct bridge_mac_list *init_bridge_list(void)
{
  struct bridge_mac_list *e;

  e = os_zalloc(sizeof(*e));

  if (e == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

  dl_list_init(&e->list);

  return e;
}

void bridge_mac_list_free(struct bridge_mac_list *e)
{
	if (e) {
    dl_list_del(&e->list);
	  os_free(e);
  }
}

void free_bridge_list(struct bridge_mac_list *ml)
{
  struct bridge_mac_list *e;

  if(ml == NULL) return;

  struct dl_list *list = &ml->list;

	while ((e = dl_list_first(list, struct bridge_mac_list, list)))
		bridge_mac_list_free(e);

  bridge_mac_list_free(ml);
}

bool check_if_src_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr)
{
  if (ml && mac_addr) {
    if (memcmp(ml->mac_tuple.src_addr, mac_addr, ETH_ALEN))
      return true;
  }

  return false;
}

struct bridge_mac_list_tuple get_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right)
{
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
    if (check_if_src_mac(e, mac_addr_left)) {
      ret.left_edge = e;
    }

    if (check_if_src_mac(e, mac_addr_right)) {
      ret.right_edge = e;
    }
	}

  return ret;
}

int add_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right)
{
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

  struct bridge_mac_list_tuple ret = get_bridge_mac(ml, mac_addr_left, mac_addr_right);
	if(ret.left_edge || ret.right_edge)
    return 0;

	src_el = os_zalloc(sizeof(*src_el));
	if (src_el == NULL) {
    log_err("os_zalloc");
    return -1;
  }

	dst_el = os_zalloc(sizeof(*dst_el));
	if (dst_el == NULL) {
    log_err("os_zalloc");
    return -1;
  }

	memcpy(src_el->mac_tuple.src_addr, mac_addr_left, ETH_ALEN);
  memcpy(src_el->mac_tuple.dst_addr, mac_addr_right, ETH_ALEN);
	dl_list_add(&ml->list, &src_el->list);

	memcpy(dst_el->mac_tuple.src_addr, mac_addr_right, ETH_ALEN);
  memcpy(dst_el->mac_tuple.dst_addr, mac_addr_left, ETH_ALEN);
	dl_list_add(&ml->list, &dst_el->list);

	return 0;
}

// int remove_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right)
// {
// 	  if (ml == NULL) {
//     log_trace("ml param is NULL");
//     return -1;
//   }

//   if (mac_addr_left == NULL) {
//     log_trace("mac_addr_left param is NULL");
//     return -1;
//   }

//   if (mac_addr_right == NULL) {
//     log_trace("mac_addr_right param is NULL");
//     return -1;
//   }

//   struct bridge_mac_list *e = get_bridge_mac(ml, mac_addr_left, mac_addr_right);
// 	if (e)
// 		bridge_mac_list_free(e);

//   return 0;
// }

// int get_bridge_tuple_list(struct bridge_mac_list *ml, const uint8_t *mac_addr_src, UT_array **tuple_list_arr)
// {
//   struct bridge_mac_tuple tuple;
//   int count = 0;
//   struct bridge_mac_list *e;
//   utarray_new(*tuple_list_arr, &tuple_list_icd);

//   if (ml == NULL) {
//     log_trace("ml param is NULL");
//     return -1;
//   }

//   struct dl_list *list = &ml->list;

//   if (mac_addr_src == NULL) {
// 	  dl_list_for_each(e, list, struct bridge_mac_list, list) {
//       utarray_push_back(*tuple_list_arr, &e->mac_tuple);
//       count ++;
//     }
//   } else {
// 	  dl_list_for_each(e, list, struct bridge_mac_list, list) {
//       if (memcmp(mac_addr_src, e->mac_tuple.left_addr, ETH_ALEN) == 0) {
//         utarray_push_back(*tuple_list_arr, &e->mac_tuple);
//         count ++;
//       } else if (memcmp(mac_addr_src, e->mac_tuple.right_addr, ETH_ALEN) == 0) {
//         memcpy(tuple.left_addr, e->mac_tuple.right_addr, ETH_ALEN);
//         memcpy(tuple.right_addr, e->mac_tuple.left_addr, ETH_ALEN);
//         utarray_push_back(*tuple_list_arr, &tuple);
//         count ++;
//       }
//     }
//   }

//   return count;
// }