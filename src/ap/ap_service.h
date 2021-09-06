/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file hostapd_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the hostapd service.
 */

#ifndef HOSTAPD_SERVICE_H
#define HOSTAPD_SERVICE_H

#include <sys/types.h>
#include <linux/if.h>
#include <stdbool.h>

#include "ap_config.h"
#include "../radius/radius_server.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/if.h"

/**
 * @brief Runs the AP service
 * 
 * @param hconf The AP configuration structure
 * @param rconf The radius configuration structure
 * @param exec_ap Flag to execute the AP process
 * @return int 0 on success, -1 on failure
 */
int run_ap(struct apconf *hconf, struct radius_conf *rconf, bool exec_ap);

/**
 * @brief Closes (terminates) AP process
 * 
 * @return true success, false otherwise
 */
bool close_ap(void);

/**
 * @brief Send a command to the AP service
 * 
 * @param socket_path The service UNIX domain path
 * @param cmd_str The command string
 * @param reply The reply
 * @return int 0 on success, -1 on failure
 */
int send_ap_command(char *socket_path, char *cmd_str, char **reply);

#endif