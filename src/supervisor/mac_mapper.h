/**************************************************************************************************
*  Filename:        mac_mapper.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     mac mapper include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef MAC_MAPPER_H
#define MAC_MAPPER_H

#include <inttypes.h>
#include <stdbool.h>

#include "bridge_list.h"

#include "../hostapd/config_generator.h"

#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"
#include "../utils/hashmap.h"

struct mac_conn_info {
  int       vlanid;
  bool      nat;
  bool      allow_connection;
	uint8_t 	pass[HOSTAPD_AP_SECRET_LEN];
	ssize_t		pass_len;
  char      ip_addr[IP_LEN];
  char      ifname[IFNAMSIZ];
  struct bridge_mac_list ml;
};

struct mac_conn {
  uint8_t mac_addr[ETH_ALEN];
  struct mac_conn_info info;
};

typedef struct hashmap_mac_conn {
    char key[ETH_ALEN];               /* key as mac address */
    struct mac_conn_info value;
    UT_hash_handle hh;         		    /* makes this structure hashable */
} hmap_mac_conn;

bool create_mac_mapper(UT_array *connections, hmap_mac_conn **hmap);
int get_mac_mapper(hmap_mac_conn **hmap, uint8_t mac_addr[ETH_ALEN], struct mac_conn_info *info);
bool put_mac_mapper(hmap_mac_conn **hmap, struct mac_conn conn);
void free_mac_mapper(hmap_mac_conn **hmap);
int get_mac_list(hmap_mac_conn **hmap, struct mac_conn **list);

#endif