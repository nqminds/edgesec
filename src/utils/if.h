/**************************************************************************************************
*  Filename:        if.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     if include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/
#ifndef IF_H_
#define IF_H_

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "linux/rtnetlink.h"
#include "utarray.h"
#include "uthash.h"
#include "os.h"

enum IF_STATE{
	IF_STATE_UNKNOWN = 0,
	IF_STATE_NOTPRESENT,
	IF_STATE_DOWN,
	IF_STATE_LOWERLAYERDOWN,
	IF_STATE_TESTING,
	IF_STATE_DORMANT,
	IF_STATE_UP,
	IF_STATE_OTHER,
};

typedef struct {
	char ifname[IFNAMSIZ];
	uint32_t ifindex;
	enum IF_STATE state;
	char link_type[LINK_TYPE_LEN];
	uint8_t ifa_family;
	char ip_addr[IP_LEN];
	char peer_addr[IP_LEN];
	char brd_addr[IP_LEN];
	uint8_t mac_addr[ETH_ALEN];
} netif_info_t;

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char			buf[1024];
};

typedef struct {
	char 						ifname[IFNAMSIZ];
	char 						ip_addr[IP_LEN];
	char 						brd_addr[IP_LEN];
} config_ifinfo_t;

typedef struct hashmap_if_conn {
    in_addr_t 			key;               			/* key as subnet */
    char 						value[IFNAMSIZ];				/* value as the interface name */
    UT_hash_handle 	hh;         		    		/* makes this structure hashable */
} hmap_if_conn;

bool ip_2_nbo(char *ip, char *subnetMask, in_addr_t *addr);

int get_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname);
bool put_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname);
void free_if_mapper(hmap_if_conn **hmap);

bool iface_exists(const char *ifname);

bool create_interface(char *if_name, char *type);
bool set_interface_ip(char *ip_addr, char *brd_addr, char *if_name);
bool set_interface_state(char *if_name, bool state);
UT_array *get_interfaces(int if_id);

#endif