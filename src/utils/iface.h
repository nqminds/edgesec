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
 * @file iface.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the network interface utilities.
 */

#ifndef IFACE_H_
#define IFACE_H_

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "utarray.h"
#include "uthash.h"
#include "allocs.h"
#include "os.h"

/**
 * @brief Create a interface object
 * 
 * @param ifname The interface string name
 * @param type The interface string type (ex. "bridge")
 * @return true on success, false otherwise
 */
bool create_interface(char *ifname, char *type);

/**
 * @brief Set the interface IP
 * 
 * @param ip_addr The IP address string
 * @param brd_addr The broadcast IP address string
 * @param ifname The interface name string
 * @return true on success, false otherwise
 */
bool set_interface_ip(char *ip_addr, char *brd_addr, char *ifname);

/**
 * @brief Set the interface state
 * 
 * @param ifname The interface name string
 * @param state The interface state value (true - "up", false - "down")
 * @return true on success, false otherwise
 */
bool set_interface_state(char *ifname, bool state);

/**
 * @brief Resets the interface
 * 
 * @param if_name The interface name string
 * @return true on success, false otherwise
 */
bool reset_interface(char *ifname);

/**
 * @brief Returns an exisiting WiFi interface name that supports VLAN
 * 
 * @param if_buf Interface working buffer
 * @return char* WiFi interface name
 */
char* get_vlan_interface(char *if_buf);

/**
 * @brief Get the array of @c struct netif_info_t for each available interface
 * 
 * @param id The intreface id, if 0 return all interfaces
 * @return UT_array* The returned array of @c struct netif_info_t
 */
UT_array *get_interfaces(int id);
#endif
