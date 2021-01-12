/**************************************************************************************************
*  Filename:        bridge_list.c
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     bridge list source file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/
#include "utils/os.h"
#include "utils/log.h"

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
	dl_list_del(&e->list);
	os_free(e);
}

void free_bridge_list(struct bridge_mac_list *ml)
{
	struct bridge_mac_list *e;
  struct dl_list *list = &ml->list;

	while ((e = dl_list_first(list, struct bridge_mac_list, list)))
		bridge_mac_list_free(e);

  bridge_mac_list_free(ml);
}

struct bridge_mac_list *get_bridge_mac(struct bridge_mac_list *ml, const char *mac_addr)
{
	struct bridge_mac_list *e;
  struct dl_list *list = &ml->list;
  if (memcmp(ml->mac_addr, mac_addr, ETH_ALEN) == 0)
    return ml;

	dl_list_for_each(e, list, struct bridge_mac_list, list) {
    if (memcmp(e->mac_addr, mac_addr, ETH_ALEN) == 0)
			return e;
	}

  return NULL;
}

int add_bridge_mac(struct bridge_mac_list *ml, const char *mac_addr)
{
	struct bridge_mac_list *e;

  if (mac_addr == NULL) {
    log_trace("mac_addr param is NULL");
    return -1;
  }

	e = get_bridge_mac(ml, mac_addr);
	if (e)
		return 0;

	e = os_zalloc(sizeof(*e));
	if (e == NULL) {
    log_err("os_zalloc");
    return -1;
  }

	memcpy(e->mac_addr, mac_addr, ETH_ALEN);

	dl_list_add(&ml->list, &e->list);
	return 0;
}

void remove_bridge_mac(struct bridge_mac_list *ml, const char *mac_addr)
{
	// struct bridge_mac_list *e;

	// e = get_bridge_mac(ml, mac_addr);
	// if (e)
	// 	bridge_mac_list_free(e);
}