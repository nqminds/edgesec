/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the ip generic interface utilities.
 */

#ifndef IPGEN_H_
#define IPGEN_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "os.h"

struct ipgenctx {
  char ipcmd_path[MAX_OS_PATH_LEN]; /**< The ip command path */
};

/**
 * @brief Initialises the ipgen context
 *
 * @param path The path string to the ip command
 * @return The ip generic context or NULL on failure.
 * Must be cleaned-up with ipgen_free_context().
 */
struct ipgenctx *ipgen_init_context(char *path);

/**
 * @brief Frees the ipgen context
 *
 * @param context The ipgen context created by ipgen_init_context()
 */
void ipgen_free_context(struct ipgenctx *context);

/**
 * @brief Creates and interface and assigns an IP
 *
 * @param context The ipgen context interface
 * @param ifname The interface name
 * @param type The interface type
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param subnet_mask The interface IP4 subnet mask
 * @return int 0 on success, -1 on failure
 */
int ipgen_create_interface(const struct ipgenctx *context, const char *ifname,
                           const char *type, const char *ip_addr,
                           const char *brd_addr, const char *subnet_mask);

/**
 * @brief Set the IP address for an interface
 *
 * @param context The ipgen context interface
 * @param ifname The interface name
 * @param ip_addr The interface IP4 address
 * @param brd_addr The interface IP4 broadcast address
 * @param subnet_mask The interface IP4 subnet mask
 * @return int 0 on success, -1 on failure
 */
int ipgen_set_interface_ip(const struct ipgenctx *context, const char *ifname,
                           const char *ip_addr, const char *brd_addr,
                           const char *subnet_mask);

/**
 * @brief Resets the interface
 *
 * @param context The ipgen context interface
 * @param ifname The interface name
 * @return int 0 on success, -1 on failure
 */
int ipgen_reset_interface(const struct ipgenctx *context, const char *ifname);
#endif
