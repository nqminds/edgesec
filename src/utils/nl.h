/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the netlink utilities.
 */

#ifndef NL_H_
#define NL_H_

#include <stdbool.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <utarray.h>
#include "linux/rtnetlink.h"

#ifdef DEBUG_LIBNL
#define NL_CB_TYPE NL_CB_DEBUG
#else
#define NL_CB_TYPE NL_CB_DEFAULT
#endif

struct nlctx {
  void *reserved;
};

struct nl80211_state {
  struct nl_sock *nl_sock;
  int nl80211_id;
};

/**
 * @brief Network wireless interface information structure
 *
 */
typedef struct {
  char ifname[IF_NAMESIZE];     /**< Interface string name */
  uint32_t ifindex;             /**< Interface index */
  uint64_t wdev;                /**< Physical interface wdev param */
  uint8_t addr[ETHER_ADDR_LEN]; /**< Interface byte MAC address */
  uint32_t wiphy;               /**< Physical interface ID */
} netiw_info_t;

struct iplink_req {
  struct nlmsghdr n;
  struct ifinfomsg i;
  char buf[1024];
};

/**
 * @brief Initialises the nl context
 *
 * @return The nl context, or NULL on error (e.g. memory allocation failure).
 * You must nl_free_context() this object when done with it.
 */
struct nlctx *nl_init_context(void);

/**
 * @brief Frees the nl context
 *
 * @param context The nl context created by nl_init_context()
 */
void nl_free_context(struct nlctx *context);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 *
 * @param if_id The intreface id, if 0 return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t.
 * You must `utarray_free()` this array when done.
 */
UT_array *nl_get_interfaces(int if_id);

/**
 * @brief Creates a new interface object
 *
 * @param if_name The interface string name
 * @param type The interface string type (ex. "bridge")
 * @return 0 on success, -1 otherwise
 */
int nl_new_interface(const char *if_name, const char *type);

/**
 * @brief Set the interface IP
 *
 * @param context The nl context
 * @param ifname The interface name string
 * @param ip_addr The IP address string
 * @param brd_addr The broadcast IP address string
 * @param subnet_mask The subnet mask (e.g. `24` for `/24`)
 * @return 0 on success, -1 otherwise
 */
int nl_set_interface_ip(const struct nlctx *context, const char *ifname,
                        const char *ip_addr, const char *brd_addr,
                        const char *subnet_mask);

/**
 * @brief Set the interface state
 *
 * @param if_name The interface name string
 * @param state The interface state value (true - "up", false - "down")
 * @return 0 on success, -1 otherwise
 */
int nl_set_interface_state(const char *if_name, bool state);

/**
 * @brief Creates and interface and assigns an IP
 *
 * @param context The nl context interface
 * @param ifname The interface name
 * @param type The interface type
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param subnet_mask The interface IP4 subnet mask
 * @return int 0 on success, -1 on failure
 */
int nl_create_interface(const struct nlctx *context, const char *ifname,
                        const char *type, const char *ip_addr,
                        const char *brd_addr, const char *subnet_mask);

/**
 * @brief Resets the interface
 *
 * @param ifname The interface name string
 * @return 0 on success, -1 otherwise
 */
int nl_reset_interface(const char *ifname);

/**
 * @brief Check if wireless physical interface has VLAN capability
 *
 * @param wiphy Wireless physical interface ID
 * @return 1 if capability present, 0 otherwise, -1 on error
 */
int iwace_isvlan(uint32_t wiphy);

/**
 * @brief Get the array of all wireless physical interfaces
 *
 * @return UT_array* The array of wireless physical interfaces
 */
UT_array *get_netiw_info(void);

/**
 * @brief Check if interface has the VLAN capability
 *
 * @param ifname Interface name string
 * @return int 0 if VLAN capable, -1 on error and 1 if not VLAN capable
 */
int nl_is_iw_vlan(const char *ifname);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 *
 * @param[out] buf Interface working buffer of at least IF_NAMESIZE bytes.
 * @return WiFi interface name (pointer to @p buf param)
 */
char *nl_get_valid_iw(char buf[static IF_NAMESIZE]);

#endif
