/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
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

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/eloop.h"
#include "../utils/utarray.h"
#include "../utils/sockctl.h"

#include "../capture/capture_service.h"

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

int run_analyser(char *ifname, struct capture_conf *config, pthread_t *pid) {
  if (run_capture_thread(ifname, config, pid) < 0) {
    log_error("run_capture_thread fail");
    return -1;
  }

  return 0;
}

int schedule_analyser(struct supervisor_context *context, int vlanid) {
  pthread_t pid;
  struct capture_conf config;
  struct vlan_conn vlan_conn;

  if (get_vlan_mapper(&context->vlan_mapper, vlanid, &vlan_conn) <= 0) {
    log_error("ifname not found for vlanid=%d", vlanid);
    return -1;
  }

  if (!vlan_conn.capture_pid) {
    os_memcpy(&config, &context->capture_config, sizeof(config));

    log_trace("Starting analyser on if=%s", vlan_conn.ifname);
    if (run_analyser(vlan_conn.ifname, &config, &pid) != 0) {
      log_error("run_analyser fail");
      return -1;
    }

    vlan_conn.capture_pid = pid;
    if (!put_vlan_mapper(&context->vlan_mapper, &vlan_conn)) {
      log_error("put_vlan_mapper fail");
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

  if (utarray_len(config_ifinfo_array) <= 1) {
    return context->default_open_vlanid;
  }

  len = utarray_len(config_ifinfo_array) - 1;
  if ((vlan_arr = (int *)os_malloc(sizeof(int) * len)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  while ((p = (config_ifinfo_t *)utarray_next(config_ifinfo_array, p)) !=
         NULL) {
    vlan_arr[idx++] = p->vlanid;
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
      log_error("execute_capture fail");
      log_debug("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
      return -1;
    }
  }

  if (os_get_timestamp(&info->join_timestamp) < 0) {
    log_error("os_get_timestamp fail");
    log_debug("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
    return -1;
  }

  log_debug("ALLOWING mac=" MACSTR " on vlanid=%d", MAC2STR(mac_addr),
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

  log_debug("REQUESTING vlanid=%d for mac=" MACSTR, alloc_vlanid,
            MAC2STR(mac_addr));

  if (mac_addr == NULL) {
    log_error("mac_addr is NULL");
    info.vlanid = -1;
    return info;
  }

  if (context == NULL) {
    log_error("context is NULL");
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
      log_error("assign_device_vlan fail");
      info.vlanid = -1;
    }

    return info;
  } else if (!context->allow_all_connections &&
             (find_mac == 1 && info.allow_connection && info.pass_len)) {
    if (save_device_vlan(context, mac_addr, &info) < 0) {
      log_error("assign_device_vlan fail");
      info.vlanid = -1;
    }

    return info;
  } else if (!context->allow_all_connections && find_mac == -1) {
    log_error("get_mac_mapper fail");
  } else if (!context->allow_all_connections &&
             (find_mac == 0 ||
              (find_mac == 1 && info.allow_connection && !info.pass_len))) {
    log_debug("mac=" MACSTR " not assigned, checking for the active tickets",
              MAC2STR(mac_addr));
    info.allow_connection = true;

    if (context->ticket != NULL) {
      // Use ticket
      log_debug("Assigning auth ticket");
      info.vlanid = context->ticket->vlanid;
      info.pass_len = context->ticket->passphrase_len;
      os_memcpy(info.pass, context->ticket->passphrase, info.pass_len);
      os_memcpy(info.label, context->ticket->device_label,
                MAX_DEVICE_LABEL_SIZE);
      free_ticket(context);
    } else {
      // Assign to default VLAN ID
      log_debug("Assigning default connection");
      info.vlanid = alloc_vlanid;
      info.pass_len = context->wpa_passphrase_len;
      os_memcpy(info.pass, context->wpa_passphrase, info.pass_len);
    }

    if (save_device_vlan(context, mac_addr, &info) < 0) {
      log_error("assign_device_vlan fail");
      info.vlanid = -1;
    }

    return info;
  }

  log_debug("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
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
      log_error("save_mac_mapper fail");
    }
  }

  if (send_events_subscriber(context, SUBSCRIBER_EVENT_AP, MACSTR " %d",
                             MAC2STR(mac_addr), status) < 0) {
    log_error("send_events_subscriber fail");
  }
}

int process_received_data(int sock, struct client_address *claddr,
                          struct supervisor_context *context) {
  uint32_t bytes_available;
  if (ioctl(sock, FIONREAD, &bytes_available) == -1) {
    log_errno("ioctl");
    return -1;
  }

  char *buf;
  if ((buf = os_malloc(bytes_available)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  ssize_t received;
  if ((received = read_socket_data(sock, buf, bytes_available, claddr, 0)) ==
      -1) {
    log_error("read_socket_data fail");
    os_free(buf);
    return -1;
  }

  UT_array *args = NULL;
  utarray_new(args, &ut_str_icd);

  log_trace("Supervisor received %ld bytes", (long)received);
  if (process_domain_buffer(buf, received, args, CMD_DELIMITER) == false) {
    log_error("process_domain_buffer fail");
    os_free(buf);
    utarray_free(args);
    return -1;
  }

  os_free(buf);

  char **arg = (char **)utarray_front(args);

  process_cmd_fn cfn;
  if ((cfn = get_command_function(*arg)) != NULL) {
    if (cfn(sock, claddr, context, args) == -1) {
      log_error("%s fail", *arg);
      utarray_free(args);
      return -1;
    }
  }

  utarray_free(args);
  return 0;
}

void eloop_read_domain_handler(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)eloop_ctx;

  struct supervisor_context *context = (struct supervisor_context *)sock_ctx;

  struct client_address claddr = {
      .type = SOCKET_TYPE_DOMAIN,
  };

  if (process_received_data(sock, &claddr, context) < 0) {
    log_error("process_received_data fail");
  }
}

void eloop_read_udp_handler(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)eloop_ctx;

  struct supervisor_context *context = (struct supervisor_context *)sock_ctx;

  struct client_address claddr = {
      .type = SOCKET_TYPE_UDP,
  };

  if (process_received_data(sock, &claddr, context) < 0) {
    log_error("process_received_data fail");
  }
}

void close_supervisor(struct supervisor_context *context) {
  if (context == NULL) {
    log_error("context param is NULL");
    return;
  }

  if (context->domain_sock != -1) {
    if (close(context->domain_sock) == -1) {
      log_errno("close");
    }
  }

  if (context->udp_sock != -1) {
    if (close(context->udp_sock) == -1) {
      log_errno("close");
    }
  }

  if (context->subscribers_array != NULL) {
    utarray_free(context->subscribers_array);
  }
}

int run_supervisor(char *server_path, unsigned int port,
                   struct supervisor_context *context) {
  if (server_path == NULL) {
    log_error("server_path param is NULL");
    return -1;
  }

  if (!port) {
    log_error("port is zero");
    return -1;
  }

  if (context == NULL) {
    log_error("context param is NULL");
    return -1;
  }

  allocate_vlan(context);

  utarray_new(context->subscribers_array, &client_address_icd);

  if ((context->domain_sock = create_domain_server(server_path)) == -1) {
    log_error("create_domain_server fail");
    return -1;
  }

  if ((context->udp_sock = create_udp_server(port)) == -1) {
    log_error("create_udp_server fail");
    return -1;
  }

  if (eloop_register_read_sock(context->eloop, context->domain_sock,
                               eloop_read_domain_handler, NULL,
                               (void *)context) == -1) {
    log_error("eloop_register_read_sock fail");
    close_supervisor(context);
    return -1;
  }

  if (eloop_register_read_sock(context->eloop, context->udp_sock,
                               eloop_read_udp_handler, NULL,
                               (void *)context) == -1) {
    log_error("eloop_register_read_sock fail");
    close_supervisor(context);
    return -1;
  }

  return 0;
}
