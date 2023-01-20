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
#include <sys/socket.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <utarray.h>

#include "subscriber_events.h"

#include <eloop.h>
#include "../utils/allocs.h"
#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/sockctl.h"

#include "../capture/capture_service.h"

#include "cmd_processor.h"
#include "network_commands.h"
#include "supervisor_utils.h"

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

    log_trace("Starting analyser on ifname=%s", vlan_conn.ifname);
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
  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  os_memcpy(&conn.info, info, sizeof(struct mac_conn_info));
  if (save_mac_mapper(context, conn) < 0) {
    log_trace("save_mac_mapper fail");
    log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
    return -1;
  }

  return 0;
}

int get_mac_ac(uint8_t *mac_addr, struct supervisor_context *context, struct identity_info *iinfo) {
  iinfo->access = IDENTITY_ACCESS_DENY;

  struct mac_conn_info info;
  int alloc_vlanid = (context->allocate_vlans)
                         ? allocate_vlan(context, mac_addr, ETHER_ADDR_LEN, VLAN_ALLOCATE_HASH)
                         : context->default_open_vlanid;

  init_default_mac_info(&info, alloc_vlanid, context->allow_all_nat);

  log_debug("REQUESTING vlanid=%d for mac=" MACSTR, alloc_vlanid,
            MAC2STR(mac_addr));

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
      return -1;
    }

    iinfo->access = IDENTITY_ACCESS_ALLOW;
  } else if (!context->allow_all_connections &&
             (find_mac == 1 && info.allow_connection && info.pass_len)) {
    if (save_device_vlan(context, mac_addr, &info) < 0) {
      log_error("assign_device_vlan fail");
      return -1;
    }

    iinfo->access = IDENTITY_ACCESS_ALLOW;
  } else if (!context->allow_all_connections && find_mac == -1) {
    log_error("get_mac_mapper fail");
    return -1;
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
      return -1;
    }

    iinfo->access = IDENTITY_ACCESS_ALLOW;
  }

  iinfo->vlanid = info.vlanid;
  iinfo->id_pass_len = info.pass_len;
  os_memcpy(iinfo->id_pass, info.pass, iinfo->id_pass_len);

  if (iinfo->access == IDENTITY_ACCESS_DENY) {
    log_debug("ACCESS DENY for mac=" MACSTR, MAC2STR(mac_addr));
  } else if(iinfo->access == IDENTITY_ACCESS_ALLOW){
    log_debug("ACCESS ALLOW for mac=" MACSTR, MAC2STR(mac_addr));
  }

  return 0;
}

int get_cert_ac(const uint8_t *identity, size_t identity_len, struct supervisor_context *context, struct identity_info *iinfo) {
  iinfo->vlanid = (context->allocate_vlans)
                         ? allocate_vlan(context, identity, identity_len, VLAN_ALLOCATE_HASH)
                         : context->default_open_vlanid;

  log_debug("REQUESTING vlanid=%d for cert=%.*s", iinfo->vlanid, identity_len, identity);
  iinfo->access = IDENTITY_ACCESS_ALLOW;

  return 0;
}

struct identity_info * get_identity_ac(const uint8_t *identity, size_t identity_len,
                                      void *mac_conn_arg) {
  if (identity == NULL) {
    log_error("identity param is NULL");
    return NULL;
  }

  if (mac_conn_arg == NULL) {
    log_error("context is NULL");
    return NULL;
  }

  struct identity_info *iinfo = (struct identity_info *) sys_zalloc(sizeof(struct identity_info));
  if ((iinfo == NULL)) {
    log_errno("sys_zalloc");
    return NULL;
  }

  if (process_identity_type(identity, identity_len, iinfo) < 0) {
    log_error("process_identity_type fail");
    free_identity_info(iinfo);
    return NULL;
  }

  struct supervisor_context *context =
      (struct supervisor_context *)mac_conn_arg;

  if (iinfo->type == IDENTITY_TYPE_MAC) {
    if (get_mac_ac(iinfo->mac_addr, context, iinfo) < 0) {
      log_error("get_mac_ac fail");
      free_identity_info(iinfo);
      return NULL;
    }
  } else if (iinfo->type == IDENTITY_TYPE_CERT) {
    if (get_cert_ac(identity, identity_len, context, iinfo) < 0) {
      log_error("get_cert_ac fail");
      free_identity_info(iinfo);
      return NULL;
    }
  } else {
    log_error("Unknown identity type");
    free_identity_info(iinfo);
    return NULL;
  }

  return iinfo;
}

void ap_service_callback(struct supervisor_context *context, uint8_t mac_addr[],
                         enum AP_CONNECTION_STATUS status) {
  struct mac_conn conn;
  struct mac_conn_info info;
  log_debug("Received AP status for mac=" MACSTR " status=%d",
            MAC2STR(mac_addr), status);
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) > 0) {
    info.status = status;
    os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
    conn.info = info;

    if (save_mac_mapper(context, conn) < 0) {
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
    context->domain_sock = -1;
  }

  if (context->udp_sock != -1) {
    if (close(context->udp_sock) == -1) {
      log_errno("close");
    }
    context->udp_sock = -1;
  }

  if (context->subscribers_array != NULL) {
    utarray_free(context->subscribers_array);
  }
  context->subscribers_array = NULL;
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

  utarray_new(context->subscribers_array, &client_address_icd);

  if ((context->domain_sock = create_domain_server(server_path)) == -1) {
    log_error("create_domain_server fail");
    close_supervisor(context);
    return -1;
  }

  if ((context->udp_sock = create_udp_server(port)) == -1) {
    log_error("create_udp_server fail");
    close_supervisor(context);
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
