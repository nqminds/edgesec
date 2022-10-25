/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the supervisor utils.
 */

#ifndef SUPERVISOR_UTILS_H
#define SUPERVISOR_UTILS_H

#include <inttypes.h>

#include "supervisor_config.h"

/**
 * @brief Allocates a VLAN ID for a given MAC address
 *
 * @param context[in] The supervisor context
 * @param mac_addr[in] The MAC address
 *
 * @return VLAN ID, -1 on failure
 */
int allocate_vlan(struct supervisor_context *context, uint8_t *mac_addr);

/**
 * @brief Save a MAC entry into the mapper
 *
 * @param context The supervisor context
 * @param conn The MAC connection structure
 *
 * @return true on success, false on failure
 */
bool save_mac_mapper(struct supervisor_context *context, struct mac_conn conn);

#endif