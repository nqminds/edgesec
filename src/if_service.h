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
 * @file if_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the interface services utilites.
 */

#ifndef IF_SERVICE_H
#define IF_SERVICE_H

#include <inttypes.h>
#include <stdbool.h>

#include "utils/if.h"
/**
 * @brief Create the subnet interface
 * 
 * @param ifinfo_array Interface info array
 * @param ignore_error Flag to ignore error if subnet already exists
 * @return true succes, false if creation fails with error
 */
bool create_subnet_ifs(UT_array *ifinfo_array, bool ignore_error);

/**
 * @brief Check if interface has the VLAN capability
 * 
 * @param ap_interface Interface name string
 * @return true if VLAN capable, false otherwise
 */
bool is_iw_vlan(const char *ap_interface);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 * 
 * @param if_buf Interface working buffer
 * @return char* WiFi interface name
 */
char* get_valid_iw(char *if_buf);

/**
 * @brief Returns the IP of the NAT interface
 * 
 * @param nat_interface The NAT interface name string
 * @param ip_buf Allocated NAT interface IP address
 * @return true if IP saved to ip_buf, false otherwise
 */
bool get_nat_if_ip(const char *nat_interface, char **ip_buf);

#endif