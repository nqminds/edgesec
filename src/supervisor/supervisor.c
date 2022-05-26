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
#include <sys/ioctl.h>
#include <libgen.h>
#include <time.h>

#include "subscriber_events.h"

#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/eloop.h"
#include "utils/utarray.h"
#include "utils/domain.h"

#include "cmd_processor.h"
#include "network_commands.h"

static const UT_icd client_address_icd = {sizeof(struct client_address), NULL,
                                          NULL, NULL};

void configure_mac_info(struct mac_conn_info *info, bool allow_connection,
                        int vlanid, ssize_t pass_len, uint8_t *pass,
                        char *label) {
  info->allow_connection = allow_connection;
  info->vlanid = vlanid;
  info->pass_len = pass_len;
  os_memcpy(info->pass, pass, info->pass_len);
  if (label != NULL) {
    os_memcpy(info->label, label, MAX_DEVICE_LABEL_SIZE);
  }
}

int run_analyser(struct capture_conf *config, pid_t *child_pid) {
  int ret;
  char **process_argv = capture_config2opt(config);
  char *proc_name;
  if (process_argv == NULL) {
    log_trace("capture_config2opt fail");
    return -1;
  }

  ret = run_process(process_argv, child_pid);

  if ((proc_name = os_strdup(basename(process_argv[0]))) == NULL) {
    log_errno("os_malloc");
    capture_freeopt(process_argv);
    return -1;
  }

  log_trace("Found capture process running with pid=%d (%s)", *child_pid,
            proc_name);
  os_free(proc_name);
  capture_freeopt(process_argv);
  return ret;
}

int schedule_analyser(struct supervisor_context *context, int vlanid) {
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

int allocate_vlan(struct supervisor_context *context) {
  int *vlan_arr = NULL;
  int vlanid, idx = 0, len;
  config_ifinfo_t *p = NULL;
  UT_array *config_ifinfo_array = context->config_ifinfo_array;

  if (!context->allocate_vlans) {
    return context->default_open_vlanid;
  }

  // Exclude the quarantine vlanid
  if (utarray_len(config_ifinfo_array) <= 2 &&
      context->quarantine_vlanid >= 0) {
    return context->default_open_vlanid;
  }

  len = utarray_len(config_ifinfo_array) - 1;
  if ((vlan_arr = (int *)os_malloc(sizeof(int) * len)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  while ((p = (config_ifinfo_t *)utarray_next(config_ifinfo_array, p)) !=
         NULL) {
    if (p->vlanid != context->quarantine_vlanid) {
      vlan_arr[idx++] = p->vlanid;
    }
  }

  vlanid = vlan_arr[os_get_random_int_range(0, len - 1)];
  os_free(vlan_arr);

  return vlanid;
}

int save_device_vlan(struct supervisor_context *context, uint8_t mac_addr[],
                     struct mac_conn_info *info) {
  struct mac_conn conn;

  if (context->exec_capture) {
    if (schedule_analyser(context, info->vlanid) < 0) {
      log_trace("execute_capture fail");
      log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
      return -1;
    }
  }

  if (os_get_timestamp(&info->join_timestamp) < 0) {
    log_trace("os_get_timestamp fail");
    log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
    return -1;
  }

  log_trace("ALLOWING mac=" MACSTR " on vlanid=%d", MAC2STR(mac_addr),
            info->vlanid);
  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  os_memcpy(&conn.info, info, sizeof(struct mac_conn_info));
  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
    return -1;
  }

  return 0;
}

struct mac_conn_info get_mac_conn_cmd(uint8_t mac_addr[], void *mac_conn_arg) {
  struct supervisor_context *context =
      (struct supervisor_context *)mac_conn_arg;
  struct mac_conn_info info;
  int alloc_vlanid = allocate_vlan(context);
  init_default_mac_info(&info, alloc_vlanid, context->allow_all_nat);

  log_trace("REQUESTING vlanid=%d for mac=" MACSTR, alloc_vlanid,
            MAC2STR(mac_addr));

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

  if (context->allow_all_connections &&
      (find_mac == 0 || (find_mac == 1 && info.allow_connection))) {
    if (find_mac == 0) {
      configure_mac_info(&info, true, alloc_vlanid, context->wpa_passphrase_len,
                         context->wpa_passphrase, NULL);
    } else if (find_mac == 1 && !info.pass_len) {
      info.pass_len = context->wpa_passphrase_len;
      os_memcpy(info.pass, context->wpa_passphrase,
                context->wpa_passphrase_len);
    }

    if (save_device_vlan(context, mac_addr, &info) < 0) {
      log_trace("assign_device_vlan fail");
      info.vlanid = -1;
    }

    return info;
  } else if (!context->allow_all_connections &&
             (find_mac == 1 && info.allow_connection && info.pass_len)) {
    if (save_device_vlan(context, mac_addr, &info) < 0) {
      log_trace("assign_device_vlan fail");
      info.vlanid = -1;
    }

    return info;
  } else if (!context->allow_all_connections && find_mac == -1) {
    log_trace("get_mac_mapper fail");
  } else if (!context->allow_all_connections &&
             (find_mac == 0 ||
              (find_mac == 1 && info.allow_connection && !info.pass_len))) {
    log_trace("mac=" MACSTR " not assigned, checking for the active tickets",
              MAC2STR(mac_addr));
    info.allow_connection = true;

    if (context->ticket != NULL) {
      // Use ticket
      log_trace("Assigning auth ticket");
      info.vlanid = context->ticket->vlanid;
      info.pass_len = context->ticket->passphrase_len;
      os_memcpy(info.pass, context->ticket->passphrase, info.pass_len);
      os_memcpy(info.label, context->ticket->device_label,
                MAX_DEVICE_LABEL_SIZE);
      free_ticket(context);
    } else {
      // Assign to default VLAN ID
      log_trace("Assigning default connection");
      info.vlanid = alloc_vlanid;
      info.pass_len = context->wpa_passphrase_len;
      os_memcpy(info.pass, context->wpa_passphrase, info.pass_len);
    }

    if (save_device_vlan(context, mac_addr, &info) < 0) {
      log_trace("assign_device_vlan fail");
      info.vlanid = -1;
    }

    return info;
  }

  log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
  info.vlanid = -1;
  return info;
}

void ap_service_callback(struct supervisor_context *context, uint8_t mac_addr[],
                         enum AP_CONNECTION_STATUS status) {
  struct mac_conn conn;
  struct mac_conn_info info;
  log_debug("Received AP status for mac=" MACSTR " status=%d",
            MAC2STR(mac_addr), status);
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) > 0) {
    info.status = status;
    os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
    conn.info = info;

    if (!save_mac_mapper(context, conn)) {
      log_trace("save_mac_mapper fail");
    }
  }

  if (send_events_subscriber(context, SUBSCRIBER_EVENT_AP, MACSTR " %d",
                             MAC2STR(mac_addr), status) < 0) {
    log_trace("send_events_subscriber fail");
  }
}

void eloop_read_sock_handler(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)eloop_ctx;

  char **ptr = NULL;
  UT_array *cmd_arr;
  process_cmd_fn cfn;
  uint32_t bytes_available;
  ssize_t num_bytes;
  struct client_address claddr;
  char *buf;
  struct supervisor_context *context = (struct supervisor_context *)sock_ctx;

  os_memset(&claddr, 0, sizeof(struct client_address));

  if (ioctl(sock, FIONREAD, &bytes_available) == -1) {
    log_errno("ioctl");
    return;
  }

  if ((buf = os_malloc(bytes_available)) == NULL) {
    log_errno("os_malloc");
    return;
  }

  utarray_new(cmd_arr, &ut_str_icd);

  if ((num_bytes = read_domain_data(sock, buf, bytes_available, &claddr, 0)) ==
      -1) {
    log_trace("read_domain_data fail");
    goto end;
  }

  log_trace("Supervisor received %ld bytes from socket length=%d",
            (long)num_bytes, claddr.len);
  if (process_domain_buffer(buf, num_bytes, cmd_arr, context->domain_delim) ==
      false) {
    log_trace("process_domain_buffer fail");
    goto end;
  }

  ptr = (char **)utarray_next(cmd_arr, ptr);

  if ((cfn = get_command_function(*ptr)) != NULL) {
    if (cfn(sock, &claddr, context, cmd_arr) == -1) {
      log_trace("%s fail", *ptr);
      goto end;
    }
  }

end:
  os_free(buf);
  utarray_free(cmd_arr);
}

void close_supervisor(struct supervisor_context *context) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return;
  }

  if (context->domain_sock != -1) {
    if (close(context->domain_sock) == -1) {
      log_errno("close");
    }
  }

  if (context->subscribers_array != NULL) {
    utarray_free(context->subscribers_array);
  }
}

int run_supervisor(char *server_path, struct supervisor_context *context) {
  allocate_vlan(context);

  utarray_new(context->subscribers_array, &client_address_icd);

  if ((context->domain_sock = create_domain_server(server_path)) == -1) {
    log_trace("create_domain_server fail");
    close_supervisor(context);
    return -1;
  }

  if (eloop_register_read_sock(context->eloop, context->domain_sock,
                               eloop_read_sock_handler, NULL,
                               (void *)context) == -1) {
    log_trace("eloop_register_read_sock fail");
    close_supervisor(context);
    return -1;
  }

  return 0;
}
