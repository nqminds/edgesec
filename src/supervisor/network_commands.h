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
 * @file network_commands.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the network commands.
 */

#ifndef NETWORK_COMMANDS_H
#define NETWORK_COMMANDS_H

#include <inttypes.h>
#include <stdbool.h>

/**
 * @brief Processes the REMOVE_BRIDGE command
 * 
 * @param sock The domain server socket
 * @param client_addr The client address for replies
 * @param context The supervisor structure instance
 * @param cmd_arr The array of received commands
 * @return ssize_t Size of reply written data
 */
ssize_t remove_bridge_cmd(struct supervisor_context *context, UT_array *cmd_arr);


#endif
