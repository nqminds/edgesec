/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file nl.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the netlink utilities.
 */

#ifndef NL_H_
#define NL_H_

#include "linux/rtnetlink.h"

#include "utarray.h"

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char				buf[1024];
};

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 * 
 * @param if_id The intreface id, if 0 return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 */
UT_array *nl_get_interfaces(int if_id);


/**
 * @brief Create a interface object
 * 
 * @param if_name The interface string name
 * @param type The interface string type (ex. "bridge")
 * @return true on success, false otherwise
 */
bool nl_create_interface(char *if_name, char *type);

/**
 * @brief Set the interface IP
 * 
 * @param ip_addr The IP address string
 * @param brd_addr The broadcast IP address string
 * @param if_name The interface name string
 * @return true on success, false otherwise
 */
bool nl_set_interface_ip(char *ip_addr, char *brd_addr, char *if_name);

/**
 * @brief Set the interface state
 * 
 * @param if_name The interface name string
 * @param state The interface state value (true - "up", false - "down")
 * @return true on success, false otherwise
 */
bool nl_set_interface_state(char *if_name, bool state);

#endif