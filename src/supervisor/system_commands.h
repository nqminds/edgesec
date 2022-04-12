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

#include "../utils/domain.h"
#include "supervisor_config.h"

enum DHCP_IP_TYPE {
  DHCP_IP_NONE = 0,
  DHCP_IP_NEW,
  DHCP_IP_OLD,
  DHCP_IP_DEL,
};

/**
 * @brief SET_IP command
 *
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address
 * @param ip_addr The IP address
 * @param ip_type The DHCP_IP_TYPE
 * @return int 0 on success, -1 on failure
 */
int set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *ip_addr, enum DHCP_IP_TYPE ip_type);

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
 * @param addr The subscriber address
 * @return 0 on success, -1 on failure
 */
int subscribe_events_cmd(struct supervisor_context *context, struct client_address *addr);

#endif