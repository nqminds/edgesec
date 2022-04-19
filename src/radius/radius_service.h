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
 * @file radius_service.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the radius service.
 */

#ifndef RADIUS_SERVICE_H
#define RADIUS_SERVICE_H

#include "../supervisor/supervisor.h"
#include "radius_server.h"

/**
 * @brief Runs the radius service
 *
 * @param rconf The radius config
 * @param radius_callback_fn The radius callback function
 * @param radius_callback_args The Radius callback arguments
 * @return Pointer to private RADIUS server context or NULL on failure
 */
struct radius_server_data *run_radius(struct radius_conf *rconf,
                                      void *radius_callback_fn,
                                      void *radius_callback_args);

/**
 * @brief Closes the radius service
 *
 * @param srv Pointer to private RADIUS server context
 */
void close_radius(struct radius_server_data *srv);

#endif
