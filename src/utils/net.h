/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file net.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the network utilities.
 */
#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "utarray.h"
#include "uthash.h"
#include "allocs.h"
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

/**
 * @brief Network interface definition structure
 * 
 */
typedef struct {
	char 			ifname[IFNAMSIZ];					/**< Interface string name */
	uint32_t 		ifindex;							/**< Interface index value */
	enum IF_STATE 	state;								/**< Interface state */
	char 			link_type[LINK_TYPE_LEN];			/**< Interface link type */
	uint8_t 		ifa_family;							/**< Interface family */
	char 			ip_addr[IP_LEN];					/**< Interface string IP address */
	char 			peer_addr[IP_LEN];					/**< Interface string peer IP address */
	char 			brd_addr[IP_LEN];					/**< Interface string IP broadcast address */
	uint8_t 		mac_addr[ETH_ALEN];					/**< Interface byte MAC address */
} netif_info_t;
