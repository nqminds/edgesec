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
#include <libgen.h>

#include "sqlite_fingerprint_writer.h"

#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/eloop.h"
#include "utils/utarray.h"
#include "utils/domain.h"

#include "cmd_processor.h"
#include "network_commands.h"

#define FINGERPRINT_DB_NAME "fingerprint" SQLITE_EXTENSION

void configure_mac_info(struct mac_conn_info *info, bool allow_connection,
                        int vlanid, ssize_t pass_len, uint8_t *pass, char *label)
{
  info->allow_connection = allow_connection;
  info->vlanid = vlanid;
  info->pass_len = pass_len;
  os_memcpy(info->pass, pass, info->pass_len);
  if (label != NULL) {
    os_memcpy(info->label, label, MAX_DEVICE_LABEL_SIZE);
  }
}

int run_analyser(struct capture_conf *config, pid_t *child_pid)
{
  int ret;
  char **process_argv = capture_config2opt(config);
  char *proc_name;
  if (process_argv == NULL) {
    log_trace("capture_config2opt fail");
    return -1;
  }

  ret = run_process(process_argv, child_pid);

  if ((proc_name = os_strdup(basename(process_argv[0]))) == NULL) {
    log_err("os_malloc");
    capture_freeopt(process_argv);
    return -1;
  }

  if (is_proc_running(proc_name) <= 0) {
    log_trace("is_proc_running fail");
    os_free(proc_name);
    capture_freeopt(process_argv);
    return -1;
  }

  log_trace("Found capture process running with pid=%d", *child_pid);
  os_free(proc_name);
  capture_freeopt(process_argv);
  return ret;
}

int schedule_analyser(struct supervisor_context *context, int vlanid)
{
  pid_t child_pid;
  struct capture_conf config;
  struct vlan_conn vlan_conn;

  if (get_vlan_mapper(&context->vlan_mapper, vlanid, &vlan_conn) <= 0) {
    log_trace("ifname not found for vlanid=%d", vlanid);
    return -1;
  }

  if (!vlan_conn.analyser_pid) {
    os_memcpy(&config, &context->capture_config, sizeof(config));

    log_trace("Starting analyser on if=%s", vlan_conn.ifname);
    os_memcpy(config.capture_interface, vlan_conn.ifname, IFNAMSIZ);

    if (run_analyser(&config, &child_pid) != 0) {
      log_trace("run_analyser fail");
      return -1;
    }

    vlan_conn.analyser_pid = child_pid;
    if (!put_vlan_mapper(&context->vlan_mapper, &vlan_conn)) {
      log_trace("put_vlan_mapper fail");
      return -1;
    }
  }

  return 0;
}

struct mac_conn_info get_mac_conn_cmd(uint8_t mac_addr[], void *mac_conn_arg)
{
  struct supervisor_context *context = (struct supervisor_context *) mac_conn_arg;
  struct mac_conn conn;
  struct mac_conn_info info;

  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  log_trace("REQUESTED vland id for mac=" MACSTR, MAC2STR(mac_addr));

  if (mac_addr == NULL) {
    log_trace("mac_addr is NULL");
    info.vlanid = -1;
    return info;
  }

  if (context == NULL) {
    log_trace("context is NULL");
    info.vlanid = -1;
    return info;
  }

  int find_mac = get_mac_mapper(&context->mac_mapper, mac_addr, &info);

  if (context->allow_all_connections && (find_mac == 0 || (find_mac == 1 && info.allow_connection))) {
    if (find_mac == 0) {
      configure_mac_info(&info, true, context->default_open_vlanid, context->wpa_passphrase_len, context->wpa_passphrase, NULL);
    } else if (find_mac == 1 && !info.pass_len) {
      info.pass_len = context->wpa_passphrase_len;
      os_memcpy(info.pass, context->wpa_passphrase, context->wpa_passphrase_len);
    }

    if (context->exec_capture) {
      if (schedule_analyser(context, info.vlanid) < 0) {
        log_trace("execute_capture fail");
        log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
        info.vlanid = -1;
        return info;
      }
    }

    if (os_get_timestamp(&info.join_timestamp) < 0) {
      log_trace("os_get_timestamp fail");
        info.vlanid = -1;
        return info;
    }

    log_trace("ALLOWING mac=" MACSTR " on default vlanid=%d", MAC2STR(mac_addr), info.vlanid);
    os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
    conn.info = info;
    if (!save_mac_mapper(context, conn)) {
      log_trace("save_mac_mapper fail");
      info.vlanid = -1;
    }

    return info;
  } else if (!context->allow_all_connections && (find_mac == 1 && info.allow_connection && info.pass_len)) {
    if (context->exec_capture) {
      if (schedule_analyser(context, info.vlanid) < 0) {
        log_trace("execute_capture fail");
        log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
        info.vlanid = -1;
        return info;
      }
    }

    if (os_get_timestamp(&info.join_timestamp) < 0) {
      log_trace("os_get_timestamp fail");
        info.vlanid = -1;
        return info;
    }

    log_trace("ALLOWING mac=" MACSTR " on vlanid=%d", MAC2STR(mac_addr), info.vlanid);
    os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
    conn.info = info;
    if (!save_mac_mapper(context, conn)) {
      log_trace("save_mac_mapper fail");
      info.vlanid = -1;
    }

    return info;
  } else if (!context->allow_all_connections && find_mac == -1) {
    log_trace("get_mac_mapper fail");
  } else if (!context->allow_all_connections && (find_mac == 0 || (find_mac == 1 && info.allow_connection && !info.pass_len))) {
    log_trace("mac=" MACSTR " not assigned, checking for the active tickets", MAC2STR(mac_addr));
    info.allow_connection = true;

    if (context->ticket != NULL) {
      // Use ticket
      log_trace("Assigning auth ticket");
      info.vlanid = context->ticket->vlanid;
      info.pass_len = context->ticket->passphrase_len;
      os_memcpy(info.pass, context->ticket->passphrase, info.pass_len);
      os_memcpy(info.label, context->ticket->device_label, MAX_DEVICE_LABEL_SIZE);
      free_ticket(context);
    } else {
      // Assign to default VLAN ID
      log_trace("Assigning default connection");
      info.vlanid = context->default_open_vlanid;
      info.pass_len = context->wpa_passphrase_len;
      os_memcpy(info.pass, context->wpa_passphrase, info.pass_len);
    }

    if (context->exec_capture) {
      if (schedule_analyser(context, info.vlanid) < 0) {
        log_trace("execute_capture fail");
        log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
        info.vlanid = -1;
        return info;
      }
    }

    if (os_get_timestamp(&info.join_timestamp) < 0) {
      log_trace("os_get_timestamp fail");
        info.vlanid = -1;
        return info;
    }

    log_trace("ALLOWING mac=" MACSTR " on vlanid=%d", MAC2STR(mac_addr), info.vlanid);
    os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
    conn.info = info;
    if (!save_mac_mapper(context, conn)) {
      log_trace("save_mac_mapper fail");
      info.vlanid = -1;
    }

    return info;
  }
  
  log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
  info.vlanid = -1;
  return info;
}

void ap_service_callback(struct supervisor_context *context, uint8_t mac_addr[], enum AP_CONNECTION_STATUS status)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  log_debug("Received AP status for mac=" MACSTR" status=%d", MAC2STR(mac_addr), status);
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) > 0) {
    info.status = status;
    os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
    conn.info = info;
    if (!put_mac_mapper(&context->mac_mapper, conn)) {
      log_trace("put_mac_mapper fail");
    }
  }
}

void eloop_read_sock_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  (void) eloop_ctx;

  char **ptr = NULL;
  UT_array *cmd_arr;
  process_cmd_fn cfn;
  struct sockaddr_un caddr;
  int addr_len;
  struct client_address addr;
  char buf[MAX_DOMAIN_RECEIVE_DATA];
  struct supervisor_context *context = (struct supervisor_context *) sock_ctx;

  utarray_new(cmd_arr, &ut_str_icd);

  os_memset(&caddr, 0, sizeof(struct sockaddr_un));

  ssize_t num_bytes = read_domain_data(sock, buf, MAX_DOMAIN_RECEIVE_DATA, &caddr, &addr_len, 0);
  if (num_bytes == -1) {
    log_trace("read_domain_data fail");
    goto end;  
  }

  addr.addr = caddr;
  addr.len = addr_len;

  log_trace("Supervisor received %ld bytes from socket length=%d", (long) num_bytes, addr_len);
  if (process_domain_buffer(buf, num_bytes, cmd_arr, context->domain_delim) == false) {
    log_trace("process_domain_buffer fail");
    goto end;
  }

  ptr = (char**) utarray_next(cmd_arr, ptr);

  if ((cfn = get_command_function(*ptr)) != NULL) {
    if (cfn(sock, &addr, context, cmd_arr) == -1) {
      log_trace("%s fail", *ptr);
      goto end;
    }
  }

end:
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
  char *db_path = NULL;

  db_path = construct_path(context->db_path, FINGERPRINT_DB_NAME);
  if (db_path == NULL) {
    log_debug("construct_path fail");
    return -1;
  }

  if (open_sqlite_fingerprint_db(db_path, &context->fingeprint_db) < 0) {
    log_trace("open_sqlite_fingerprint_db fail");
    os_free(db_path);
    return -1;
  }

  os_free(db_path);

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
