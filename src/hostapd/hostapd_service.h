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

#include "hostapd_config.h"
#include "../radius/radius_server.h"
#include "../utils/os.h"
#include "../utils/if.h"

/**
 * @brief Runs the hostapd service (executes the compiled hostapd process binary)
 * 
 * @param hconf The hostapd configuration structure
 * @param rconf The radius configuration structure
 * @param ctrl_if_path The path of the hostapd control interface
 * @return int 0 on success, -1 on error
 */
int run_hostapd(struct hostapd_conf *hconf, struct radius_conf *rconf, char *ctrl_if_path);

/**
 * @brief Closes (terminates) hostapd process
 * 
 * @param sock Not used
 * @return true success, false otherwise
 */
bool close_hostapd(int sock);

#endif