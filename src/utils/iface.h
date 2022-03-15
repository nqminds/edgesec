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
 * @file iface.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the network interface utilities.
 */

#ifndef IFACE_H_
#define IFACE_H_

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "utarray.h"
#include "uthash.h"
#include "allocs.h"
#include "os.h"

#ifdef WITH_UCI_SERVICE
#include "uci_wrt.h"
#elif WITH_NETLINK_SERVICE
#include "nl.h"
#elif WITH_IP_GENERIC_SERVICE
#include "ipgen.h"
#endif

struct iface_context {
#ifdef WITH_UCI_SERVICE
  struct uctx *context;
#elif WITH_NETLINK_SERVICE
  struct nlctx *context;
#elif WITH_IP_GENERIC_SERVICE
  struct ipgenctx *context;
#endif
};

/**
 * @brief Initialises the interface context
 * 
 * @param params The parameters for interface context
 * @return struct iface_context* The interface context
 */
struct iface_context* iface_init_context(void* params);

/**
 * @brief Initialises the interface context
 * 
 * @param context The interface context
 */
void iface_free_context(struct iface_context *xontext);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 * 
 * @param if_buf Interface working buffer
 * @return char* WiFi interface name
 */
char* iface_get_vlan(char *if_buf);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 * 
 * @param id The interface name, if NULL return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 */
UT_array *iface_get(char *ifname);

/**
 * @brief Creates and interface and assigns an IP
 * 
 * @param context The interface context
 * @param ifname The interface name
 * @param type The interface type
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param subnet_mask The interface IP4 subnet mask
 * @return int 0 on success, -1 on failure
 */
int iface_create(struct iface_context *context, char *ifname,
                 char *type, char *ip_addr, char *brd_addr,
                 char *subnet_mask);

/**
 * @brief Commits the interface changes
 * 
 * @param context The interface context
 * @return int 0 on success, -1 on failure
 */
int iface_commit(struct iface_context *context);

/**
 * @brief Resets an interface
 * 
 * @param context The interface context
 * @param ifname The interface name
 * @return int 0 on success, -1 on failure
 */
int reset_interface(struct iface_context *context, char *ifname);
#endif