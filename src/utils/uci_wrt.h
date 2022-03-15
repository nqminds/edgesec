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
 * @file uci.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the uci utilities.
 */

#ifndef UCI_H_
#define UCI_H_

#include "uci.h"

#include "utarray.h"
#include "os.h"
#include "squeue.h"

struct uctx {
  struct uci_context *uctx;
  char path[MAX_OS_PATH_LEN];
};

/**
 * @brief Initialises the uci context
 * 
 * @param path The path string to the config folder
 * @return struct uctx* The uci context
 */
struct uctx* uwrt_init_context(char *path);

/**
 * @brief Frees the uci context
 * 
 * @param context The uci context
 */
void uwrt_free_context(struct uctx *context);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 * 
 * @param context The uci context
 * @param ifname The interface name, if NULL return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 */
UT_array *uwrt_get_interfaces(struct uctx *context, char *ifname);

/**
 * @brief Creates and interface and assigns an IP
 * 
 * @param context The uci context
 * @param ifname The interface name
 * @param type The interface type
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param netmask The interface IP4 netmask
 * @return int 0 on success, -1 on failure
 */
int uwrt_create_interface(struct uctx *context, char *ifname, char *type,
                          char *ip_addr, char *brd_addr, char *netmask);

/**
 * @brief Commit a uci section
 * 
 * @param context The uci context
 * @param context The uci section
 * @return int 0 on success, -1 on failure
 */
int uwrt_commit_section(struct uctx *context, char *section);

/**
 * @brief Generates a dnsmasq uci instance
 * 
 * @param context The uci context
 * @param ifname_queue The interface queue
 * @param server_array The array of servers
 * @param leasefile The lease file path string
 * @param scriptfile The script file path string
 * @return int 0 on success, -1 on failure
 */
int uwrt_gen_dnsmasq_instance(struct uctx *context, struct string_queue *ifname_queue,
  UT_array *server_array, char *leasefile, char *scriptfile);

#endif