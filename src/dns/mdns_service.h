/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @brief File containing the definition of mDNS service structures.
 */

#ifndef MDNS_SERVICE_H
#define MDNS_SERVICE_H

#include "dns_config.h"
#include "reflection_list.h"
#include "mdns_mapper.h"
#include "command_mapper.h"
#include "../utils/iface_mapper.h"

/**
 * @brief The mDNS context.
 *
 */
struct mdns_context {
  struct reflection_list *rif4;      /**< IP4 reflection list. */
  struct reflection_list *rif6;      /**< IP6 reflection list. */
  hmap_mdns_conn *imap;              /**< mDNS mapper. */
  hmap_vlan_conn *vlan_mapper;       /**< WiFi VLAN to interface mapper */
  hmap_command_conn *command_mapper; /**< The command mapper */
  UT_array *pctx_list;               /**< The list of pcap context */
  struct mdns_conf config;           /**< mDNS config. */
  char cap_id[MAX_RANDOM_UUID_LEN];  /**< Auto generated capture ID */
  char supervisor_control_path[MAX_OS_PATH_LEN]; /**< Specifies the path to the
                                               UNIX domain supervisor control
                                               path */
  int sfd; /**< Domain client file descriptor */
};

/**
 * @brief Runs the mDNS forwarder service
 *
 * @param config The mDNS config structure
 * @return int 0 on success, -1 on failure
 */
int run_mdns(struct mdns_context *context);

/**
 * @brief Runs the mDNS forwarder service thread
 *
 * @param mdns_config The mDNS config structure
 * @param supervisor_control_path The UNIX domain supervisor control path
 * @param vlan_mapper The VLAN mapper object
 * @param id The returned thread id
 * @return int 0 on success, -1 on failure
 */
int run_mdns_thread(struct mdns_conf *mdns_config,
                    char *supervisor_control_path, hmap_vlan_conn *vlan_mapper,
                    pthread_t *id);
/**
 * @brief Closes mDNS service
 *
 * @param context The mDNS context structure
 * @return 0 on success, -1 on failure
 */
int close_mdns(struct mdns_context *context);

#endif
