/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the system commands.
 */

#ifndef SYSTEM_COMMANDS_H
#define SYSTEM_COMMANDS_H

#include <sys/un.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../utils/sockctl.h"
#include "supervisor_config.h"

enum DHCP_IP_TYPE {
  DHCP_IP_NONE = 0,
  DHCP_IP_NEW,
  DHCP_IP_OLD,
  DHCP_IP_DEL,
  DHCP_IP_ARP,
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
char *ping_cmd(void);

/**
 * @brief SUBSCRIBE_EVENTS command
 *
 * @param context The supervisor structure instance
 * @param addr The subscriber address
 * @return 0 on success, -1 on failure
 */
int subscribe_events_cmd(struct supervisor_context *context,
                         struct client_address *addr);

#endif
