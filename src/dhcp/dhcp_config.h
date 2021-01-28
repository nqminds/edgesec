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
 * @file dhcp_config.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of dhcp configuration structures.
 */
#ifndef DHCP_CONFIG_H
#define DHCP_CONFIG_H

#include "../utils/os.h"
#include "../utils/utarray.h"

#define DHCP_LEASE_TIME_SIZE  10

typedef struct config_dhcpinfo_t {
	int       			        vlanid;                                     /**< Interface VLAN ID */
	char 						ip_addr_low[IP_LEN];		                /**< Interface string IP address lower bound*/
	char 						ip_addr_upp[IP_LEN];		                /**< Interface string IP address upper bound*/
	char 						subnet_mask[IP_LEN];	                    /**< Interface string IP subnet mask */
  char 						    lease_time[DHCP_LEASE_TIME_SIZE];	        /**< Interface lease time string */
} config_dhcpinfo_t;

/**
 * @brief The dhcp configuration structures.
 * 
 */
struct dhcp_conf {
  char dhcp_conf_path[MAX_OS_PATH_LEN];                 /**< The dhcp config path string */
  char dhcp_script_path[MAX_OS_PATH_LEN];               /**< The dhcp executable script path string */
  UT_array  *config_dhcpinfo_array;                     /**< Array containg the mapping between VLAN ID sand IP address range. */
};
#endif