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
 * @file engine.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the app configuration structure.
 */
#ifndef ENGINE_H
#define ENGINE_H

// #include <net/if.h>
#include <inttypes.h>
#include <stdbool.h>

#include "config.h"
#include "supervisor/supervisor_config.h"

/**
 * @brief Initialises the app context structure
 *
 * @param app_config The app config structure
 * @param ctx The app context structure
 * @return 0 on success, -1 otherwise
 */
int init_context(struct app_config *app_config, struct supervisor_context *ctx);

/**
 * @brief Executes the edgesec WiFi networking engine. Creates subnets and starts the supervisor, radius servers and hostapd service.
 *
 * @param app_config The app configuration structures, setting WiFi network config params.
 * @return @c true if succes, @c false if a service fails to start.
 */
bool run_engine(struct app_config *app_config);

#endif