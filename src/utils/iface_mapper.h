/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the interface mapper utilities.
 */

#ifndef IFACE_MAPPER_H_
#define IFACE_MAPPER_H_

#include <net/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include <utarray.h>
#include <uthash.h>
#include "allocs.h"
#include "os.h"
#include "net.h"

#define LINK_TYPE_LEN 64

enum IF_STATE {
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
  char ifname[IF_NAMESIZE];           /**< Interface string name */
  uint32_t ifindex;                   /**< Interface index value */
  enum IF_STATE state;                /**< Interface state */
  char link_type[LINK_TYPE_LEN];      /**< Interface link type */
  uint8_t ifa_family;                 /**< Interface family */
  char ip_addr[OS_INET_ADDRSTRLEN];   /**< Interface string IP4 address */
  char ip_addr6[OS_INET6_ADDRSTRLEN]; /**< Interface string IP6 address */
  char peer_addr[OS_INET_ADDRSTRLEN]; /**< Interface string peer IP address */
  char brd_addr[OS_INET_ADDRSTRLEN];  /**< Interface string IP broadcast address
                                       */
  uint8_t mac_addr[ETHER_ADDR_LEN];   /**< Interface byte MAC address */
} netif_info_t;

/**
 * @brief Interface configuration info structure
 *
 */
typedef struct config_ifinfo_t {
  int vlanid;                        /**< Interface VLAN ID */
  char ifname[IF_NAMESIZE];          /**< Interface string name */
  char brname[IF_NAMESIZE];          /**< Bridge string name */
  char ip_addr[OS_INET_ADDRSTRLEN];  /**< Interface string IP address */
  char brd_addr[OS_INET_ADDRSTRLEN]; /**< Interface string IP broadcast address
                                      */
  char subnet_mask[OS_INET_ADDRSTRLEN]; /**< Interface string IP subnet mask */
} config_ifinfo_t;

/**
 * @brief Subnet to interface connection mapper
 *
 */
typedef struct hashmap_if_conn {
  in_addr_t key;           /**< key as subnet */
  char value[IF_NAMESIZE]; /**< value as the interface name */
  UT_hash_handle hh;       /**< makes this structure hashable */
} hmap_if_conn;

/**
 * @brief MAC connection structure
 *
 */
struct vlan_conn {
  int vlanid;               /**< the VLAN ID */
  char ifname[IF_NAMESIZE]; /**< the interface name */
  pthread_t capture_pid;    /**< Capture thread descriptor */
};

/**
 * @brief VLAN to interface connection mapper
 *
 */
typedef struct hashmap_vlan_conn {
  int key;                /**< VLAN id as subnet */
  struct vlan_conn value; /**< value as the vlan_conn structure */
  UT_hash_handle hh;      /**< makes this structure hashable */
} hmap_vlan_conn;

/**
 * @brief Get the interface name corresponding to an IP address of the subnet
 *
 * @param hmap The interface connection mapper object
 * @param subnet The IP address of the subnet
 * @param ifname The returned interface name
 * @return int 1 if found, 0 not found, -1 on error
 */
int get_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname);

/**
 * @brief Insertes an interface and subnet IP value into the interface
 * connection mapper
 *
 * @param hmap The interface connection mapper object
 * @param subnet The IP address of the subnet
 * @param ifname The interface name
 * @return true on success, false otherwise
 */
bool put_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname);

/**
 * @brief Frees the interface connection mapper object
 *
 * @param hmap The interface connection mapper object
 */
void free_if_mapper(hmap_if_conn **hmap);

/**
 * @brief Get the vlan connection structure corresponding to a VLAN ID
 *
 * @param hmap The VLAN ID to vlan connection mapper object
 * @param vlanid The VLAN ID
 * @param conn The returned VLAN connection structure
 * @return int 1 if found, 0 not found, -1 on error
 */
int get_vlan_mapper(hmap_vlan_conn **hmap, int vlanid, struct vlan_conn *conn);

/**
 * @brief Makes a copy of the VLAn mapper structure
 *
 * @param hmap The VLAN ID to vlan connection mapper object
 * @param copy The copied VLAN mapper
 * @return int 1 if found, 0 not found, -1 on error
 */
int copy_vlan_mapper(hmap_vlan_conn **hmap, hmap_vlan_conn **copy);

/**
 * @brief Inserts a vlan connection structure and VLAN ID value into the
 * interface connection mapper
 *
 * @param hmap The VLAN ID to interface connection mapper object
 * @param conn The VLAN connection structure
 * @return true on success, false otherwise
 */
bool put_vlan_mapper(hmap_vlan_conn **hmap, struct vlan_conn *conn);

/**
 * @brief Frees the VLAN ID to interface connection mapper object
 *
 * @param hmap The VLAN ID to interface connection mapper object
 */
void free_vlan_mapper(hmap_vlan_conn **hmap);

/**
 * @brief Get the interface name from an IP string
 *
 * @param[in] config_ifinfo_array The list of IP subnets
 * @param[in] ip The input IP address
 * @param[out] ifname The returned interface name (buffer has to be
 * preallocated at least the size of config_ifinfo_t::ifname)
 * @return 0 on success, -1 otherwise
 */
int get_ifname_from_ip(UT_array *config_ifinfo_array, char *ip, char *ifname);

/**
 * @brief Get the bridge name from an IP string
 *
 * @param[in] config_ifinfo_array The list of IP subnets
 * @param[in] ip_addr The input IP address
 * @param[out] brname The returned bridge name (buffer has to be
 * preallocated to at least the size of config_ifinfo_t::brname).
 * @return 0 on success, -1 otherwise
 */
int get_brname_from_ip(UT_array *config_ifinfo_array, char *ip_addr,
                       char *brname);

/**
 * @brief Create the subnet to interface mapper
 *
 * @param config_ifinfo_array The connection info array
 * @param hmap The subnet to interface mapper
 * @return true on success, false otherwise
 */
bool create_if_mapper(UT_array *config_ifinfo_array, hmap_if_conn **hmap);

/**
 * @brief Create the VLAN ID to interface mapper
 *
 * @param config_ifinfo_array The connection info array
 * @param hmap The VLAN ID to interface mapper
 * @return true on success, false otherwise
 */
bool create_vlan_mapper(UT_array *config_ifinfo_array, hmap_vlan_conn **hmap);

/**
 * @brief Initialise the interface names
 *
 * @param config_ifinfo_array The connection info array
 * @param ifname The interface name prefix
 * @param brname The bridge name prefix
 * @return 0 on success, -1 otherwise
 */
int init_ifbridge_names(UT_array *config_ifinfo_array, char *ifname,
                        char *brname);
#endif
