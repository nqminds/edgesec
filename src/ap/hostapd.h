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
 * @file hostapd.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of hostapd config generation utilities.
 * 
 * Defines function that generate the hostapd daemon configuration file and
 * manages (execute, kill and signal) the hostapd process.
 */

#ifndef HOSTAPD_H
#define HOSTAPD_H

#include <sys/types.h>
#include <net/if.h>
#include <stdbool.h>

#include "ap_config.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../radius/radius_server.h"

/**
 * @brief Generates and saves the hostapd configuration files
 * 
 * @param hconf The hostapd configuration structure
 * @param rconf The radius configuration structure
 * @return true if config file saved, false otherwise
 */
bool generate_hostapd_conf(struct apconf *hconf, struct radius_conf *rconf);

/**
 * @brief Generates and save the VLAN configuration file
 * 
 * @param vlan_file The VLAN configuration file path
 * @param interface The WiFi AP interface name
 * @return true  if VLAN config file saved, false otherwise
 */
bool generate_vlan_conf(char *vlan_file, char *interface);

/**
 * @brief Executes the hostapd process
 * 
 * @param hconf The hostapd process config structure
 * @return int 0 on success, -1 on failure
 */
int run_ap_process(struct apconf *hconf);

/**
 * @brief Signal the AP process to reload the config
 * 
 * @param hconf The hostapd process config structure
 * @return int 0 on success, -1 on failure
 */
int signal_ap_process(struct apconf *hconf);

/**
 * @brief Terminate the AP service
 * 
 * @return bool true on success, false otherwise 
 */
bool kill_ap_process(void);

#endif