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

enum VLAN_ALLOCATION_TYPE { VLAN_ALLOCATE_RANDOM = 0, VLAN_ALLOCATE_HASH };

/**
 * @brief Allocates a VLAN ID for a given MAC address
 *
 * @param context[in] The supervisor context
 * @param addr[in] The address
 * @param addr_len[in] The address length
 * @param type[in] The VLAN allocation type
 *
 * @return VLAN ID, -1 on failure
 */
int allocate_vlan(struct supervisor_context *context, const uint8_t *mac_addr,
                  size_t addr_len, enum VLAN_ALLOCATION_TYPE type);

/**
 * @brief Save a MAC entry into the mapper
 *
 * @param context The supervisor context
 * @param conn The MAC connection structure
 *
 * @return 0 on success, -1 on failure
 */
int save_mac_mapper(struct supervisor_context *context, struct mac_conn conn);
#endif
