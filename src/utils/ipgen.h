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
 * @file ipgen.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the ip generic interface utilities.
 */

#ifndef IPGEN_H_
#define IPGEN_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "os.h"

struct ipgenctx {
  char ipcmd_path[MAX_OS_PATH_LEN];      /**< The ip command path */
};

/**
 * @brief Initialises the ipgen context
 * 
 * @param path The path string to the ip command
 * @return struct ipgenctx* The ip generic context
 */
struct ipgenctx* ipgen_init_context(char *path);


/**
 * @brief Frees the ipgen context
 * 
 * @param context The ipgen context
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
int ipgen_create_interface(struct ipgenctx *context, char *ifname, char *type,
						char *ip_addr, char *brd_addr, char *subnet_mask);

/**
 * @brief Resets the interface
 * 
 * @param context The ipgen context interface
 * @param ifname The interface name
 * @return int 0 on success, -1 on failure
 */
int ipgen_reset_interface(struct ipgenctx *context, char *ifname);
#endif