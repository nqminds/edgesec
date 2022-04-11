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
 * @file monitor_commands.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the monitor commands.
 */

#ifndef MONITOR_COMMANDS_H
#define MONITOR_COMMANDS_H

#include <inttypes.h>
#include <stdbool.h>

#include "../capture/capture_config.h"

/**
 * @brief SET_ALERT command
 *
 * @param context The supervisor structure instance
 * @param meta The alert meta structure
 * @param info The info buffer
 * @param info_size The info buffer size
 * @return int 0 on success, -1 on failure
 */
int set_alert_cmd(struct supervisor_context *context, struct alert_meta *meta,
                        uint8_t *info, size_t info_size);

/**
 * @brief SET_FINGERPRINT command
 *
 * @param context The supervisor structure instance
 * @param src_mac_addr The source MAC address string
 * @param dst_mac_addr The destination MAC address string
 * @param protocol The protocol string
 * @param fingerprint The fingerprint string
 * @param timestamp The timestamp 64 bit value
 * @param query The query string
 * @return int 0 on success, -1 on failure
 */
int set_fingerprint_cmd(struct supervisor_context *context, char *src_mac_addr,
                        char *dst_mac_addr, char *protocol, char *fingerprint,
                        uint64_t timestamp, char *query);

/**
 * @brief QUERY_FINGERPRINT command
 *
 * @param context The supervisor structure instance
 * @param mac_addr The MAC address string
 * @param timestamp The timestamp 64 bit value
 * @param op The operator string
 * @param protocol The protocol string
 * @param out The output string
 * @return ssize_t the sizeo fo the output buffer, -1 on failure
 */
ssize_t query_fingerprint_cmd(struct supervisor_context *context, char *mac_addr, uint64_t timestamp,
                        char *op, char *protocol, char **out);

#endif