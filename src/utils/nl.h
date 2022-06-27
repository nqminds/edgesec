/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the definition of the netlink utilities.
 */

#ifndef NL_H_
#define NL_H_

#include <linux/if.h>
#include <netinet/if_ether.h>
#include "linux/rtnetlink.h"

#include "utarray.h"

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
  char ifname[IFNAMSIZ];  /**< Interface string name */
  uint32_t ifindex;       /**< Interface index */
  uint64_t wdev;          /**< Physical interface wdev param */
  uint8_t addr[ETH_ALEN]; /**< Interface byte MAC address */
  uint32_t wiphy;         /**< Physical interface ID */
} netiw_info_t;

struct iplink_req {
  struct nlmsghdr n;
  struct ifinfomsg i;
  char buf[1024];
};

/**
 * @brief Initialises the nl context
 *
 * @return struct nlctx* The nl context
 */
struct nlctx *nl_init_context(void);

/**
 * @brief Frees the nl context
 *
 * @param context The nl context
 */
void nl_free_context(struct nlctx *context);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 *
 * @param if_id The intreface id, if 0 return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 */
UT_array *nl_get_interfaces(int if_id);

/**
 * @brief Creates a new interface object
 *
 * @param if_name The interface string name
 * @param type The interface string type (ex. "bridge")
 * @return true on success, false otherwise
 */
bool nl_new_interface(char *if_name, char *type);

/**
 * @brief Set the interface IP
 *
 * @param ip_addr The IP address string
 * @param brd_addr The broadcast IP address string
 * @param if_name The interface name string
 * @return true on success, false otherwise
 */
bool nl_set_interface_ip(char *ip_addr, char *brd_addr, char *if_name);

/**
 * @brief Set the interface state
 *
 * @param if_name The interface name string
 * @param state The interface state value (true - "up", false - "down")
 * @return true on success, false otherwise
 */
bool nl_set_interface_state(char *if_name, bool state);

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
int nl_create_interface(struct nlctx *context, char *ifname, char *type,
                        char *ip_addr, char *brd_addr, char *subnet_mask);

/**
 * @brief Resets the interface
 *
 * @param if_name The interface name string
 * @return 0 on success, -1 otherwise
 */
int nl_reset_interface(char *ifname);

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
 * @param ifname Interface name string
 * @return int 0 if VLAN capable, -1 on error and 1 if not VLAN capable
 */
int nl_is_iw_vlan(const char *ifname);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 *
 * @param buf Interface working buffer
 * @return char* WiFi interface name
 */
char *nl_get_valid_iw(char *buf);

#endif
