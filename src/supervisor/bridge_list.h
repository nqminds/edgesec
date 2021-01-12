/**************************************************************************************************
*  Filename:        bridge_list.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     bridge list include file
*
*  Copyright (C) 2020 NQMCYber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef BRIDGE_LIST_H
#define BRIDGE_LIST_H

#include "../utils/list.h"
#include "../utils/os.h"

struct bridge_mac_list {
  char mac_addr[ETH_ALEN];
  struct dl_list list;
};

struct bridge_mac_list *init_bridge_list(void);
void free_bridge_list(struct bridge_mac_list *ml);
int add_bridge_mac(struct bridge_mac_list *ml, const char *mac_addr);
void remove_bridge_mac(struct bridge_mac_list *ml, const char *mac_addr);

#endif