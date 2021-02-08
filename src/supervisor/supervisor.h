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
 * @file supervisor.c
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the supervisor service.
 */

#ifndef SUPERVISOR_H
#define SUPERVISOR_H

#include "supervisor_config.h"

/**
 * @brief Executes the supervisor service
 * 
 * @param server_path The domain socket path
 * @param context The supervisor structure
 * @return int The domain socket
 */
int run_supervisor(char *server_path, struct supervisor_context *context);

/**
 * @brief Closes the supervisor service
 * 
 * @param sock The domain socket
 * @return true on success, false otherwise
 */
bool close_supervisor(int sock);

#endif