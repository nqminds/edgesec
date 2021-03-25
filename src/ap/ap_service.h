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
#include "../utils/os.h"
#include "../utils/if.h"

/**
 * @brief Runs the AP service
 * 
 * @param hconf The AP configuration structure
 * @param rconf The radius configuration structure
 * @param ctrl_if_path The path of the AP control interface
 * @return char* The pointer to the statically allocated process name, NULL on failure
 */
char* run_ap(struct apconf *hconf, struct radius_conf *rconf, char *ctrl_if_path);

/**
 * @brief Closes (terminates) AP process
 * 
 * @return true success, false otherwise
 */
bool close_ap(void);

#endif