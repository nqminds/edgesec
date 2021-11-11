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
 * @file mdns_service.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of mDNS service structures.
 */

#ifndef MDNS_SERVICE_H
#define MDNS_SERVICE_H

#include "../supervisor/supervisor_config.h"

/**
 * @brief Runs the mDNS service
 * 
 * @param context The supervisor context structure
 * @return int 0 on success, -1 on failure
 */
int run_mdns(struct supervisor_context *context);

/**
 * @brief Closes mDNS service
 * 
 * @param context The mDNS context structure
 * @return 0 on success, -1 on failure
 */
int close_mdns(struct mdns_context *context);

#endif
