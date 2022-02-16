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
 * @file net.h 
 * @author Alexandru Mereacre
 * @brief File containing the definition of the network utilities.
 */

#ifndef NET_H_
#define NET_H_

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
 * @brief Checks whether a string denotes a IPv4 address
 * 
 * @param ip The IP in fromat x.y.z.q
 * @return true if the string is an IP, false otherwise 
 */
bool validate_ipv4_string(char *ip);

/**
 * @brief IP string to @c struct in_addr_t converter
 * 
 * @param ip The IP address string
 * @param subnetMask The IP address subnet mask
 * @param addr The output @c struct in_addr_t value
 * @return 0 on success, -1 on failure
 */
int ip_2_nbo(char *ip, char *subnetMask, in_addr_t *addr);

/**
 * @brief IP string to buffer
 * 
 * @param ip The IP address string
 * @param buf The output buffer of size IP_ALEN
 * @return 0 on success, -1 on failure
 */
int ip4_2_buf(char *ip, uint8_t *buf);

/**
 * @brief Convert a 32 bit number IP to an IP string (string needs to be freed)
 * 
 * @param addr The IP in 32 bit format
 * @param ip The input buffer to store the IP
 * @return char* Pointer to the returned IP
 */
const char *bit32_2_ip(uint32_t addr, char *ip);

/**
 * @brief Convert the in_addr encoded IP4 address to an IP string (string needs to be freed)
 * 
 * @param addr The in_addr encoded IP
 * @param ip The input buffer to store the IP
 * @return char* Pointer to the returned IP
 */
const char *inaddr4_2_ip(struct in_addr *addr, char *ip);

/**
 * @brief Convert the in6_addr encoded IP6 address to an IP string (string needs to be freed)
 * 
 * @param addr The in6_addr encoded IP
 * @param ip The input buffer to store the IP
 * @return char* Pointer to the returned IP
 */
const char *inaddr6_2_ip(struct in6_addr *addr, char *ip);

#endif