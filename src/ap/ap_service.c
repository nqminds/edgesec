/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file hostapd_service.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the hostapd service.
 */
#include <unistd.h>

#include "ap_config.h"
#include "hostapd.h"
#include "radius/radius_server.h"
#include "utils/os.h"
#include "utils/if.h"
#include "utils/log.h"

char* run_ap(struct apconf *hconf, struct radius_conf *rconf, char *ctrl_if_path)
{
  if (!generate_vlan_conf(hconf->vlan_file, hconf->interface)) {
    log_trace("generate_vlan_conf fail");
    return NULL;
  }

  if (!generate_hostapd_conf(hconf, rconf)) {
    unlink(hconf->vlan_file);
    log_trace("generate_hostapd_conf fail");
    return NULL;
  }

  return run_ap_process(hconf, ctrl_if_path);
}

bool close_ap(void)
{
  return kill_ap_process();
}
