/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the network interface utilities.
 */

#ifndef IFACEU_H_
#define IFACEU_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/**
 * @brief if_nametoindex from net/if.h
 *
 */
unsigned int iface_nametoindex(const char *ifname);

/**
 * @brief Check if interface exists
 *
 * @param ifname The interface name string
 * @return true if it exists, false otherwise
 */
bool iface_exists(const char *ifname);
#endif
