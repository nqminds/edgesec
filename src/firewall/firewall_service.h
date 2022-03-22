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
 * @file firewall_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the firewall service commands.
 */

#ifndef FIREWALL_SERVICE_H
#define FIREWALL_SERVICE_H

#include <inttypes.h>
#include <stdbool.h>

#include "../supervisor/supervisor_config.h"
#include "../utils/utarray.h"
#include "../utils/hashmap.h"

/**
 * @brief Initialises the firewall service
 * 
 * @param context The supervisor context
 * @return 0 on success, -1 on failure
 */
int fw_init(struct supervisor_context *context);

/**
 * @brief Frees the firewall service
 * 
 * @param context The supervisor context
 */
void fw_free(struct supervisor_context *context);

/**
 * @brief Set the ip forward os system param
 * 
 * @return int 0 on success, -1 on failure
 */

int fw_set_ip_forward(void);

#endif