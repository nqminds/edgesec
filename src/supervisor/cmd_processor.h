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
 * @file cmd_processor.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the command processor functions.
 */

#ifndef CMD_PROCESSOR_H
#define CMD_PROCESSOR_H

#include <sys/types.h>
#include <stdbool.h>

#include "utils/utarray.h"

#define CMD_DELIMITER   		0x20

#define CMD_PING        		"PING"
#define CMD_HOSTAPD_CTRLIF      "HOSTAPD_IF"
#define CMD_ACCEPT_MAC			"ACCEPT_MAC"
#define CMD_DENY_MAC			"DENY_MAC"
#define CMD_ADD_NAT				"ADD_NAT"
#define CMD_REMOVE_NAT			"REMOVE_NAT"
#define CMD_ASSIGN_PSK			"ASSIGN_PSK"
#define CMD_GET_MAP				"GET_MAP"
#define CMD_GET_ALL				"GET_ALL"
#define CMD_SAVE_ALL			"SAVE_ALL"
#define CMD_SET_IP				"SET_IP"
#define CMD_ADD_BRIDGE			"ADD_BRIDGE"
#define CMD_REMOVE_BRIDGE		"REMOVE_BRIDGE"

/**
 * @brief Processes the domain command string
 * 
 * @param domain_buffer The domain command string
 * @param domain_buffer_len The domain command string length
 * @param cmd_arr The processed command array
 * @return true on success, false otherwise
 */
bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len, UT_array *cmd_arr);

#endif