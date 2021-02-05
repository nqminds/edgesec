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

#include "bridge_list.h"

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

bool compare_mac_in_list(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right)
{
  if (ml && mac_addr_left &&  mac_addr_right) {
    int left_left_comp = memcmp(ml->mac_tuple.left_addr, mac_addr_left, ETH_ALEN);
    int right_right_comp = memcmp(ml->mac_tuple.right_addr, mac_addr_right, ETH_ALEN);
    int left_right_comp = memcmp(ml->mac_tuple.left_addr, mac_addr_right, ETH_ALEN);
    int right_left_comp = memcmp(ml->mac_tuple.right_addr, mac_addr_left, ETH_ALEN);
    
    if ((!left_left_comp && !right_right_comp) || (!left_right_comp && !right_left_comp))
      return true;
  }

  return false;
}

struct bridge_mac_list *get_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right)
{
	struct bridge_mac_list *e;

  if (ml == NULL) {
    log_trace("ml param is NULL");
    return NULL;
  }

  if (mac_addr_left == NULL) {
    log_trace("mac_addr_left param is NULL");
    return NULL;
  }

  if (mac_addr_right == NULL) {
    log_trace("mac_addr_right param is NULL");
    return NULL;
  }

  struct dl_list *list = &ml->list;
  if (compare_mac_in_list(ml, mac_addr_left, mac_addr_right))
    return ml;

	dl_list_for_each(e, list, struct bridge_mac_list, list) {
    if (compare_mac_in_list(e, mac_addr_left, mac_addr_right))
			return e;
	}

  return NULL;
}

int add_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right)
{
	struct bridge_mac_list *e;

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

	if(get_bridge_mac(ml, mac_addr_left, mac_addr_right))
    return 0;

	e = os_zalloc(sizeof(*e));
	if (e == NULL) {
    log_err("os_zalloc");
    return -1;
  }

	memcpy(e->mac_tuple.left_addr, mac_addr_left, ETH_ALEN);
  memcpy(e->mac_tuple.right_addr, mac_addr_right, ETH_ALEN);

	dl_list_add(&ml->list, &e->list);
	return 0;
}

int remove_bridge_mac(struct bridge_mac_list *ml, const uint8_t *mac_addr_left, const uint8_t *mac_addr_right)
{
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

  struct bridge_mac_list *e = get_bridge_mac(ml, mac_addr_left, mac_addr_right);
	if (e)
		bridge_mac_list_free(e);

  return 0;
}

int get_bridge_tuple_list(struct bridge_mac_list *ml, struct bridge_mac_tuple **tuple_list)
{
  int count = 0, idx = 0;
  struct bridge_mac_tuple *ptr = NULL;
  struct bridge_mac_list *e;
  *tuple_list = NULL;

  if (ml == NULL) {
    log_trace("ml param is NULL");
    *tuple_list = NULL;
    return 0;
  }

  struct dl_list *list = &ml->list;
  count += dl_list_len(list);

  if (count) {
    ptr = (struct bridge_mac_tuple *) os_malloc(count * sizeof(struct bridge_mac_tuple));
	  dl_list_for_each(e, list, struct bridge_mac_list, list) {
      memcpy(ptr[idx].left_addr, e->mac_tuple.left_addr, ETH_ALEN);
      memcpy(ptr[idx].right_addr, e->mac_tuple.right_addr, ETH_ALEN);
      idx ++;
    }
  }
  
  *tuple_list = ptr;
  return count;
}