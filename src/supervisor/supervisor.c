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
 * @file supervisor.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the supervisor service.
 */

#include <stdbool.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>


#include "utils/log.h"
#include "utils/os.h"
#include "utils/eloop.h"
#include "utils/utarray.h"

#include "domain_server.h"
#include "cmd_processor.h"

void eloop_read_sock_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  char **ptr = NULL;
  UT_array *cmd_arr;
  char buf[MAX_DOMAIN_RECEIVE_DATA];
  struct supervisor_context *context = (struct supervisor_context *) sock_ctx;

  utarray_new(cmd_arr, &ut_str_icd);

  char *client_addr = os_malloc(sizeof(struct sockaddr_un));
  ssize_t num_bytes = read_domain_data(sock, buf, 100, client_addr);
  if (num_bytes == -1) {
    log_trace("read_domain_data fail");
    goto end;  
  }

  log_trace("Supervisor received %ld bytes from %s", (long) num_bytes, client_addr);
  if (process_domain_buffer(buf, num_bytes, cmd_arr) == false) {
    log_trace("process_domain_buffer fail");
    goto end;
  }

  ptr = (char**) utarray_next(cmd_arr, ptr);

  if (!strcmp(*ptr, CMD_PING)) {
    if (process_ping_cmd(sock, client_addr) == -1) {
      log_trace("process_ping_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_HOSTAPD_CTRLIF)) {
    if (process_hostapd_ctrlif_cmd(sock, client_addr, context) == -1) {
      log_trace("process_hostapd_ctrlif_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_ACCEPT_MAC)) {
    if (process_accept_mac_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_accept_mac_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_DENY_MAC)) {
    if (process_deny_mac_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_deny_mac_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_ADD_NAT)) {
    if (process_add_nat_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_add_nat_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_REMOVE_NAT)) {
    if (process_remove_nat_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_remove_nat_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_ASSIGN_PSK)) {
    if (process_assign_psk_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_assign_psk_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_GET_MAP)) {
    if (process_get_map_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_get_map_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_GET_ALL)) {
    if (process_get_all_cmd(sock, client_addr, context) == -1) {
      log_trace("process_get_all_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_SET_IP)) {
    if (process_set_ip_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_set_ip_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_ADD_BRIDGE)) {
    if (process_add_bridge_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_add_bridge_cmd fail");
      goto end;
    }
  } else if (!strcmp(*ptr, CMD_REMOVE_BRIDGE)) {
    if (process_remove_bridge_cmd(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("process_remove_bridge_cmd fail");
      goto end;
    }
  } else {
    log_debug("supervisor received unknown command");
  }

end:
  os_free(client_addr);
  utarray_free(cmd_arr);
}

bool close_supervisor(int sock)
{
  if (sock != -1) {
    if (close(sock) == -1) {
      log_err("close");
      return false;
    }
  }

  return true;
}

int run_supervisor(char *server_path, struct supervisor_context *context)
{
  int sock;

  if ((sock = create_domain_server(server_path)) == -1) {
    log_trace("create_domain_server fail");
    return -1;
  }

  if (eloop_register_read_sock(sock, eloop_read_sock_handler, NULL, (void *)context) ==  -1) {
    log_trace("eloop_register_read_sock fail");
    close_supervisor(sock);
    return -1;
  }

  return sock;
}
