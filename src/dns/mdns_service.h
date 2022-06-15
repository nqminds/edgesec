/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file mdns_service.h
 * @author Alexandru Mereacre
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
