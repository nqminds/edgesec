/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of hostapd config generation utilities.
 *
 * Defines function that generate the hostapd daemon configuration file and
 * manages (execute, kill and signal) the hostapd process.
 */

#ifndef HOSTAPD_H
#define HOSTAPD_H

#include <stdbool.h>
#include <sys/types.h>

#include "../radius/radius_server.h"
#include "../radius/radius_config.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "ap_config.h"

/**
 * @brief Generates and saves the hostapd configuration files
 *
 * @param hconf The hostapd configuration structure
 * @param rconf The radius configuration structure
 * @return 0 if config file saved, -1 otherwise
 */
int generate_hostapd_conf(struct apconf *hconf, struct radius_conf *rconf);

/**
 * @brief Generates and save the VLAN configuration file
 *
 * @param vlan_file The VLAN configuration file path
 * @param interface The WiFi AP interface name
 * @return 0 if VLAN config file saved, -1 otherwise
 */
int generate_vlan_conf(char *vlan_file, char *interface);

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
int signal_ap_process(const struct apconf *hconf);

/**
 * @brief Terminate the AP service
 *
 * @return bool true on success, false otherwise
 */
bool kill_ap_process(void);

#endif
