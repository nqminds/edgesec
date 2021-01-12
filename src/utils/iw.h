/**************************************************************************************************
*  Filename:        iw.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     iw include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef IW_H_
#define IW_H_

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>

#include "utarray.h"
#include "if.h"


#ifdef DEBUG_LIBNL
#define NL_CB_TYPE NL_CB_DEBUG
#else
#define NL_CB_TYPE NL_CB_DEFAULT
#endif

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

typedef struct {
	char ifname[IFNAMSIZ];
	uint32_t ifindex;
	uint64_t wdev;
	uint8_t addr[ETH_ALEN];
	uint32_t wiphy;
} netiw_info_t;

bool iwace_isvlan(uint32_t wiphy);
UT_array *get_netiw_info(void);

#endif