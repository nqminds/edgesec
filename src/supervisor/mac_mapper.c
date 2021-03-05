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
 * @file mac_mapper.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the mac mapper.
 */
#include <stdbool.h>

#include "utils/os.h"
#include "utils/log.h"
#include "utils/utarray.h"
#include "utils/uthash.h"

#include "mac_mapper.h"
#include "bridge_list.h"

int get_mac_mapper(hmap_mac_conn **hmap, uint8_t mac_addr[ETH_ALEN], struct mac_conn_info *info)
{
	hmap_mac_conn *s;

  if (hmap == NULL) {
		log_trace("hmap param is NULL");
		return -1;
  }

	if(mac_addr == NULL) {
		log_trace("mac_addr param is NULL");
		return -1;
	}

	HASH_FIND(hh, *hmap, mac_addr, ETH_ALEN, s);

	if (s != NULL) {
		*info = s->value;
    return 1;
  }
 
  return 0;
}

bool put_mac_mapper(hmap_mac_conn **hmap, struct mac_conn conn)
{
  hmap_mac_conn *s;

  if (hmap == NULL) {
		log_trace("hmap param is NULL");
		return false;
  }

  HASH_FIND(hh, *hmap, conn.mac_addr, ETH_ALEN, s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_mac_conn *) os_malloc(sizeof(hmap_mac_conn));
		if (s == NULL) {
			log_err_ex("os_malloc");
		}

		// Copy the key and value
    memcpy(s->key, conn.mac_addr, ETH_ALEN);
		s->value = conn.info;

		// HASH_ADD_STR(hmap, key, s);
    HASH_ADD(hh, *hmap, key[0], ETH_ALEN, s);
  } else {
		// Copy the value
    s->value = conn.info;
	}

  return true;
}

void free_mac_mapper(hmap_mac_conn **hmap)
{
	hmap_mac_conn *current, *tmp;

	HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current);  							/* delete it (users advances to next) */
    os_free(current);            						/* free it */
  }
}

bool create_mac_mapper(UT_array *connections, hmap_mac_conn **hmap)
{
  struct mac_conn *p = NULL;
  
  if (connections != NULL) {
    while(p = (struct mac_conn *) utarray_next(connections, p)) {
      log_trace("Adding mac=" MACSTR " with vlanid=%d ifname=%s nat=%d", MAC2STR(p->mac_addr), p->info.vlanid, p->info.ifname, p->info.nat);

      if (!put_mac_mapper(hmap, *p)) {
        log_trace("put_mac_mapper fail");
        free_mac_mapper(hmap);
        return false;
      }
    }
  }

  return true;
}

int get_mac_list(hmap_mac_conn **hmap, struct mac_conn **list)
{
 	hmap_mac_conn *current, *tmp;

  int total_entries = HASH_COUNT(*hmap), count = 0;

  if (!total_entries)
    return 0;

  struct mac_conn *ptr = (struct mac_conn *) os_malloc(total_entries * sizeof(struct mac_conn));

	HASH_ITER(hh, *hmap, current, tmp) {
    memcpy(ptr[count].mac_addr, current->key, ETH_ALEN);
    ptr[count].info = current->value;
    count ++;
  }

  *list = ptr;

  return total_entries;
}