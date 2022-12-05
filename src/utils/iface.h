/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the network interface utilities.
 */

#ifndef IFACE_H_
#define IFACE_H_

#include <stdbool.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <utarray.h>
#include <uthash.h>
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
 * @return The interface context. Must be freed by iface_free_context().
 */
struct iface_context *iface_init_context(void *params);

/**
 * @brief Initialises the interface context
 *
 * @param context The interface context
 */
void iface_free_context(struct iface_context *context);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 *
 * @param[out] if_buf Interface working buffer of at least size IF_NAMESIZE.
 * @return WiFi interface name (pointer to @p if_buf param), or NULL on error.
 */
char *iface_get_vlan(char if_buf[static IF_NAMESIZE]);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 *
 * @param[in] ifname The interface name, if NULL return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t.
 * Must be freed with utarray_free() when done.
 */
UT_array *iface_get(const char *ifname);

/**
 * @brief Get the IP4 addresses for a given interface
 *
 * @param context The interface context
 * @param[in] brname The bridge name
 * @param[in] ifname The interface name
 * @return UT_array* The returned array of IP4 strings.
 * Must be freed with utarray_free() when done.
 */
UT_array *iface_get_ip4(const struct iface_context *context, const char *brname,
                        const char *ifname);

/**
 * @brief Creates and interface and assigns an IP
 *
 * @param context The interface context
 * @param brname The bridge name
 * @param ifname The interface name
 * @param type The interface type
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param subnet_mask The interface IP4 subnet mask
 * @return int 0 on success, -1 on failure
 */
int iface_create(const struct iface_context *context, const char *brname,
                 const char *ifname, const char *type, const char *ip_addr,
                 const char *brd_addr, const char *subnet_mask);

/**
 * @brief Sets the IP4 for a given interface
 *
 * @param context The interface context
 * @param brname The bridge name
 * @param ifname The interface name
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param subnet_mask The interface IP4 subnet mask
 * @return int 0 on success, -1 on failure
 */
int iface_set_ip4(const struct iface_context *context, const char *brname,
                  const char *ifname, const char *ip_addr, const char *brd_addr,
                  const char *subnet_mask);

/**
 * @brief Commits the interface changes
 *
 * @param context The interface context
 * @return int 0 on success, -1 on failure
 */
int iface_commit(const struct iface_context *context);

/**
 * @brief Resets an interface
 *
 * @param context The interface context
 * @param ifname The interface name
 * @return int 0 on success, -1 on failure
 */
int reset_interface(const struct iface_context *context, const char *ifname);
#endif
