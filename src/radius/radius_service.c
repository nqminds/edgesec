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
 * @file radius_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the radius service.
 */

#include "../supervisor/mac_mapper.h"

#include "../utils/os.h"
#include "../utils/log.h"
#include "radius_server.h"

static hmap_mac_conn *mac_mapper;
static bool *allow_all_connections;
static int *default_open_vlanid;
static char *wpa_passphrase;

struct mac_conn_info get_mac_conn(uint8_t mac_addr[])
{
  struct mac_conn_info info;

  log_trace("RADIUS requested vland id for mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(mac_addr));

  int find_mac = get_mac_mapper(&mac_mapper, mac_addr, &info);

  if (!find_mac || *allow_all_connections) {
    log_trace("RADIUS allowing mac=%02x:%02x:%02x:%02x:%02x:%02x on default vlanid=%d", MAC2STR(mac_addr), *default_open_vlanid);
    info.vlanid = *default_open_vlanid;
    strcpy(info.pass, wpa_passphrase);
    info.pass_len = strlen(wpa_passphrase);
    return info;
  } else if (find_mac == 1) {
    if (info.allow_connection) {
      log_trace("RADIUS allowing mac=%02x:%02x:%02x:%02x:%02x:%02x on vlanid=%d", MAC2STR(mac_addr), info.vlanid);
      return info;
    }
  } else if (find_mac == -1) {
    log_trace("get_mac_mapper fail");
  }

  log_trace("RADIUS rejecting mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(mac_addr));
  info.vlanid = -1;
  return info;
}
