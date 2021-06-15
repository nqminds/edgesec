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
 * @file iw.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the wireless interface utilities.
 */

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

/**
 * @brief Network wireless interface information structure
 * 
 */
typedef struct {
	char ifname[IFNAMSIZ];				/**< Interface string name */
	uint32_t ifindex;					/**< Interface index */
	uint64_t wdev;						/**< Physical interface wdev param */
	uint8_t addr[ETH_ALEN];				/**< Interface byte MAC address */
	uint32_t wiphy;						/**< Physical interface ID */
} netiw_info_t;

/**
 * @brief Check if wireless physical interface has VLAN capability
 * 
 * @param wiphy Wireless physical interface ID
 * @return true if capability present, false otherwise
 */
bool iwace_isvlan(uint32_t wiphy);

/**
 * @brief Get the array of all wireless physical interfaces
 * 
 * @return UT_array* The array of wireless physical interfaces
 */
UT_array *get_netiw_info(void);

/**
 * @brief Check if interface has the VLAN capability
 * 
 * @param ap_interface Interface name string
 * @return int 0 if VLAN capable, -1 on error and 1 if not VLAN capable
 */
int is_iw_vlan(const char *ap_interface);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 * 
 * @param if_buf Interface working buffer
 * @return char* WiFi interface name
 */
char* get_valid_iw(char *if_buf);

#endif