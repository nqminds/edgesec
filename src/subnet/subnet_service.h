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
 * @file subnet_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the subnet interface services utilites.
 */

#ifndef SUBNET_SERVICE_H_
#define SUBNET_SERVICE_H_

#include <inttypes.h>
#include <stdbool.h>

#include "../utils/iface.h"

/**
 * @brief Create the subnet interface
 * 
 * @param ifinfo_array Interface info array
 * @param ignore_error Flag to ignore error if subnet already exists
 * @return true succes, false if creation fails with error
 */
bool create_subnet_ifs(UT_array *ifinfo_array, bool ignore_error);

/**
 * @brief Returns the IP of the NAT interface
 * 
 * @param nat_interface The NAT interface name string
 * @param ip_buf Allocated NAT interface IP address
 * @return true if IP saved to ip_buf, false otherwise
 */
bool get_nat_if_ip(const char *nat_interface, char *ip_buf);

/**
 * @brief Create the subnet to interface mapper
 * 
 * @param config_ifinfo_array The connection info array
 * @param hmap The subnet to interface mapper
 * @return true on success, false otherwise
 */
bool create_if_mapper(UT_array *config_ifinfo_array, hmap_if_conn **hmap);

/**
 * @brief Create the VLAN ID to interface mapper
 * 
 * @param config_ifinfo_array The connection info array
 * @param hmap The VLAN ID to interface mapper
 * @return true on success, false otherwise
 */
bool create_vlan_mapper(UT_array *config_ifinfo_array, hmap_vlan_conn **hmap);

/**
 * @brief Initialises interface name param in connection info array
 * 
 * @param config_ifinfo_array The connection info array
 * @param if_bridge The interface array
 * @return true on success, false otherwise
 */
bool init_ifbridge_names(UT_array *config_ifinfo_array, char *if_bridge);
#endif