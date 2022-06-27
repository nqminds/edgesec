/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @brief File containing the definition of the firewall structures.
 */

#ifndef FIREWALL_CONFIG_H
#define FIREWALL_CONFIG_H

#include <inttypes.h>
#include <stdbool.h>

#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/hashmap.h"
#include "../utils/iface_mapper.h"

#ifdef WITH_UCI_SERVICE
#include "../utils/uci_wrt.h"
#else
#include "../utils/iptables.h"
#endif

struct firewall_conf {
  char firewall_bin_path[MAX_OS_PATH_LEN]; /**< The firewall binary path string
                                            */
};

struct fwctx {
  hmap_if_conn *if_mapper;          /**< WiFi subnet to interface mapper */
  hmap_vlan_conn *vlan_mapper;      /**< WiFi VLAN to interface mapper */
  hmap_str_keychar *hmap_bin_paths; /**< Mapper for paths to systems binaries */
  UT_array *config_ifinfo_array;    /**< @c config_ifinfo_array from @c struct
                                       app_config */
  char *nat_bridge;
  char *nat_interface;
  bool exec_firewall;
  char *firewall_bin_path; /**< The firewall binary path string */
#ifdef WITH_UCI_SERVICE
  struct uctx *ctx;
#else
  struct iptables_context *ctx;
#endif
};
#endif
