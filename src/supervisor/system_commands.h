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
 * @file system_commands.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the system commands.
 */

#ifndef SYSTEM_COMMANDS_H
#define SYSTEM_COMMANDS_H

#include <sys/un.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * @brief SET_IP command
 * 
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param ip_addr The IP address
 * @param add if add = true then add IP to MAC entry, otherwise remove
 * @return int 0 on success, -1 on failure
 */
int set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *ip_addr, bool add);

/**
 * @brief SUPERVISOR_PING command
 * 
 * @return char* the ping reply string, NULL on failure
 */
char* ping_cmd(void);

/**
 * @brief SUBSCRIBE_EVENTS command
 * 
 * @param context The supervisor structure instance
 * @param addr Client address
 * @param addr_len Client address length
 * @return 0 on success, -1 on failure
 */
int subscribe_events_cmd(struct supervisor_context *context, struct sockaddr_un *addr, int addr_len);

#endif