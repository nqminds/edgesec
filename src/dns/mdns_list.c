/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file mdns_list.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of mdns list utils.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mdns_list.h"

#include "../utils/allocs.h"
#include "../utils/os.h"

struct mdns_list* init_mdns_list(void)
{
  struct mdns_list *mlist;

  if ((mlist = os_zalloc(sizeof(struct mdns_list))) == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

  os_memset(&mlist->info, 0, sizeof(struct mdns_list_info));

  dl_list_init(&mlist->list);

  return mlist;
}

void free_mdns_list_el(struct mdns_list* el)
{
  if (el != NULL) {
    dl_list_del(&el->list);
    os_free(el->info.name);
	os_free(el);
  }
}

void free_mdns_list(struct mdns_list* mlist)
{
  struct mdns_list* el;

  while ((el = dl_list_first(&mlist->list, struct mdns_list, list)) != NULL) {
    free_mdns_list_el(el);
  }

  free_mdns_list_el(mlist);
}

int push_mdns_list(struct mdns_list* mlist, struct mdns_list_info *info)
{
  struct mdns_list *el;

  if (mlist == NULL) {
    log_debug("mlist param is NULL");
    return -1;
  }

  if (info == NULL) {
    log_debug("info param is NULL");
    return -1;
  }

  if (info->name == NULL) {
    log_trace("name param is NULL");
    return -1;
  }

  dl_list_for_each(el, &mlist->list, struct mdns_list, list) {
    if (el != NULL) {
      if (el->info.request == info->request && strcmp(el->info.name, info->name) == 0) {
        return 0;
      }
    }
  }

  if ((el = init_mdns_list()) == NULL) {
    log_debug("init_mdns_list fail");
    return -1;
  }

  os_memcpy(&el->info, &info, sizeof(struct mdns_list_info));

  if ((el->info.name = os_strdup(info->name)) == NULL) {
    log_err("os_strdup");
    free_mdns_list_el(el);
    return -1;
  }

  dl_list_add_tail(&mlist->list, &el->list);

  return 0;
}

int check_mdns_list_request(struct mdns_list* mlist, enum MDNS_REQUEST_TYPE request)
{
  struct mdns_list *el;

  if (mlist == NULL) {
    log_debug("mlist param is NULL");
    return -1;
  }

  dl_list_for_each(el, &mlist->list, struct mdns_list, list) {
    if (el != NULL) {
      if (el->info.request == request) {
        return 1;
      }
    }
  }

  return 0;
}