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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>

#include "supervisor/mac_mapper.h"
#include "supervisor/supervisor.h"

#include "utils/os.h"
#include "utils/log.h"
#include "radius_server.h"

static struct supervisor_context *context = NULL;

struct mac_conn_info get_mac_conn(uint8_t mac_addr[])
{
  struct mac_conn_info info;

  log_trace("RADIUS requested vland id for mac=" MACSTR, MAC2STR(mac_addr));

  int find_mac = get_mac_mapper(&context->mac_mapper, mac_addr, &info);

  if (find_mac == 0 && context->allow_all_connections) {
    log_trace("RADIUS allowing mac=" MACSTR " on default vlanid=%d", MAC2STR(mac_addr), context->default_open_vlanid);
    info.vlanid = context->default_open_vlanid;
    info.pass_len = context->wpa_passphrase_len;
    memcpy(info.pass, context->wpa_passphrase, info.pass_len);
    return info;
  } else if (find_mac == 1) {
    if (info.allow_connection) {
      log_trace("RADIUS allowing mac=" MACSTR " on vlanid=%d", MAC2STR(mac_addr), info.vlanid);
      return info;
    }
  } else if (find_mac == -1) {
    log_trace("get_mac_mapper fail");
  }

  log_trace("RADIUS rejecting mac=" MACSTR, MAC2STR(mac_addr));
  info.vlanid = -1;
  return info;
}

struct radius_server_data *run_radius(struct radius_conf *rconf, struct supervisor_context *pcontext)
{
  context = pcontext;
  struct radius_client *client = init_radius_client(rconf, get_mac_conn);

  return radius_server_init(rconf->radius_port, client);
}

void close_radius(struct radius_server_data *srv)
{
  if (srv)
    radius_server_deinit(srv);
}
