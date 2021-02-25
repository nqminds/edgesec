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
 * @file dhcp_service.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of dhcp service configuration utilities.
 */
#include "dnsmasq.h"
#include "dhcp_config.h"
#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

int run_dhcp(char *dhcp_bin_path, struct dhcp_conf *dconf,
  char *interface, UT_array *dns_server_array, char *domain_server_path)
{
  if (!generate_dhcp_configs(dconf, interface, dns_server_array, domain_server_path)) {
    log_trace("generate_dhcp_configs fail");
    return -1;
  }

  return run_dhcp_process(dhcp_bin_path, dconf->dhcp_conf_path);
}

bool close_dhcp(int sock)
{
  // // Kill any running hostapd process
  // if (!kill_process("hostapd")) {
  //   log_trace("kill_process fail");
  //   return false;
  // }

  return true;

}