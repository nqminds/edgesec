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
 * @file capture_config.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the capture config structures.
 */

#ifndef CAPTURE_CONFIG_H
#define CAPTURE_CONFIG_H

#include <sys/types.h>
#include <net/if.h>
#include <stdbool.h>

/**
 * @brief The capture configuration structure
 * 
 */
struct capture_conf {
  char capture_interface[IFNAMSIZ];                           /**< The capture interface name (any - to capture on all interfaces) */
  int promiscuous;                                            /**< Specifies whether the interface is to be put into promiscuous mode. If promisc is non-zero, promiscuous mode will be set, otherwise it will not be set */
  int buffer_timeout;                                         /**< Specifies the packet buffer timeout, as a non-negative value, in milliseconds. (See pcap(3PCAP) for an explanation of the packet buffer timeout.) */ 
};

#endif