/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the implementation of dhcp service configuration
 * utilities.
 */
#include "dnsmasq.h"
#include "dhcp_config.h"

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

int run_dhcp(struct dhcp_conf *dconf, UT_array *dns_server_array,
             char *supervisor_control_path, bool exec_dhcp) {
  if (generate_dnsmasq_conf(dconf, dns_server_array) < 0) {
    log_trace("generate_dnsmasq_conf fail");
    return -1;
  }

  if (generate_dnsmasq_script(dconf->dhcp_script_path,
                              supervisor_control_path) < 0) {
    log_trace("generate_dnsmasq_script fail");
    return -1;
  }

  if (exec_dhcp)
    return (run_dhcp_process(dconf->dhcp_bin_path, dconf->dhcp_conf_path) ==
            NULL)
               ? -1
               : 0;
  else
    return signal_dhcp_process(dconf->dhcp_bin_path);
}

bool close_dhcp(void) { return kill_dhcp_process(); }

int clear_dhcp_lease(char *mac_addr, struct dhcp_conf *dconf) {
  return clear_dhcp_lease_entry(mac_addr, dconf->dhcp_leasefile_path);
}
