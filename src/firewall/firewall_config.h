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
 * @file firewall_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the firewall structures.
 */

#ifndef FIREWALL_CONFIG_H
#define FIREWALL_CONFIG_H

#include <inttypes.h>
#include <stdbool.h>

#include "../utils/utarray.h"
#include "../utils/hashmap.h"
#include "../utils/iface_mapper.h"

#ifdef WITH_UCI_SERVICE
#include "../utils/uci_wrt.h"
#else
#include "../utils/iptables.h"
#endif

struct fwctx {
  hmap_if_conn    *if_mapper;                                 /**< WiFi subnet to interface mapper */
  hmap_vlan_conn  *vlan_mapper;                               /**< WiFi VLAN to interface mapper */
  hmap_str_keychar *hmap_bin_paths;                           /**< Mapper for paths to systems binaries */
  UT_array        *config_ifinfo_array;                       /**< @c config_ifinfo_array from @c struct app_config */
  char *nat_interface;
  bool exec_firewall;
#ifdef WITH_UCI_SERVICE
  struct uctx* ctx;
#else
  struct iptables_context* ctx;
#endif
};
#endif