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
#include <errno.h>
#include <sys/ioctl.h>

#include "ap_config.h"
#include "hostapd.h"

#include "../supervisor/supervisor_config.h"
#include "../radius/radius_server.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/eloop.h"
#include "../utils/if.h"
#include "../utils/log.h"
#include "../utils/domain.h"

#define AP_REPLY_TIMEOUT 10

#define GENERIC_AP_COMMAND_REPLY  "OK"
#define PING_AP_COMMAND           "PING"
#define PING_AP_COMMAND_REPLY     "PONG"
#define ATTACH_AP_COMMAND         "ATTACH"
#define DENYACL_ADD_COMMAND       "DENY_ACL ADD_MAC"
#define DENYACL_DEL_COMMAND       "DENY_ACL DEL_MAC"

#define AP_STA_DISCONNECTED       "AP-STA-DISCONNECTED"
#define AP_STA_CONNECTED          "AP-STA-CONNECTED"

typedef void (*ap_service_fn)(struct supervisor_context *context, uint8_t mac_addr[], enum AP_CONNECTION_STATUS status);

int send_ap_command(char *socket_path, char *cmd_str, char **reply)
{
  int sfd;
  uint32_t bytes_available;
  ssize_t send_count, rec_count;
  struct timeval timeout;
  fd_set readfds, masterfds;
  char *rec_data, *trimmed;
  timeout.tv_sec = AP_REPLY_TIMEOUT;
  timeout.tv_usec = 0;

  *reply = NULL;

  if ((sfd = create_domain_client(NULL)) == -1) {
    log_debug("create_domain_client fail");
    return -1;
  }

  FD_ZERO(&masterfds);
  FD_SET(sfd, &masterfds);
  os_memcpy(&readfds, &masterfds, sizeof(fd_set));

  log_trace("Sending to socket_path=%s", socket_path);
  send_count = write_domain_data_s(sfd, cmd_str, strlen(cmd_str), socket_path);
  if (send_count < 0) {
    log_err("sendto");
    close(sfd);
    return -1;
  }

  if ((size_t)send_count != strlen(cmd_str)) {
    log_err("write_domain_data_s fail");
    close(sfd);
    return -1;
  }

  log_debug("Sent %d bytes to %s", send_count, socket_path);

  errno = 0;
  if (select(sfd + 1, &readfds, NULL, NULL, &timeout) < 0) {
    log_err("select");
    close(sfd);
    return -1;
  }

  if(FD_ISSET(sfd, &readfds)) {
    if (ioctl(sfd, FIONREAD, &bytes_available) == -1) {
      log_err("ioctl");
      close(sfd);
      return -1;
    }

    log_trace("Bytes available=%u", bytes_available);
    rec_data = os_zalloc(bytes_available + 1);
    if (rec_data == NULL) {
      log_err("os_zalloc");
      close(sfd);
      return -1;
    }

    rec_count = read_domain_data_s(sfd, rec_data, bytes_available, socket_path, MSG_DONTWAIT);

    if (rec_count < 0) {
      log_trace("read_domain_data_s fail");
      close(sfd);
      os_free(rec_data);
      return -1;
    }

    if ((trimmed = rtrim(rec_data, NULL)) == NULL) {
      log_trace("rtrim fail");
      close(sfd);
      os_free(rec_data);
      return -1;
    }

    *reply = os_strdup(trimmed);
  } else {
    log_debug("Socket timeout");
    close(sfd);
    return -1;
  }

  close(sfd);
  os_free(rec_data);

  return 0;
}

int ping_ap_command(struct apconf *hconf)
{
  char *reply = NULL;

  if (send_ap_command(hconf->ctrl_interface_path, PING_AP_COMMAND, &reply) < 0) {
    log_trace("send_ap_command fail");
    return -1;
  }

  if (strcmp(reply, PING_AP_COMMAND_REPLY) != 0) {
    log_trace(PING_AP_COMMAND_REPLY" reply doesn't match %s", reply);
    os_free(reply);
    return -1;
  }

  os_free(reply);
  return 0;
}

int denyacl_ap_command(struct apconf *hconf, char *cmd, char *mac_addr)
{
  char *buffer;
  char *reply = NULL;

  if (mac_addr == NULL) {
    log_trace("mac_addr is NULL");
    return -1;
  }

  if ((buffer = os_zalloc(strlen(cmd) + strlen(mac_addr) + 1)) == NULL) {
    log_err("os_zalloc");
    return -1;
  }

  sprintf(buffer, "%s %s", cmd, mac_addr);
  if (send_ap_command(hconf->ctrl_interface_path, buffer, &reply) < 0) {
    log_trace("send_ap_command fail");
    return -1;
  }

  if (strcmp(reply, GENERIC_AP_COMMAND_REPLY) != 0) {
    log_trace(GENERIC_AP_COMMAND_REPLY" reply doesn't match %s", reply);
    os_free(reply);
    return -1;
  }

  os_free(reply);
  return 0;
}

int denyacl_add_ap_command(struct apconf *hconf, char *mac_addr)
{
  return denyacl_ap_command(hconf, DENYACL_ADD_COMMAND, mac_addr);
}

int denyacl_del_ap_command(struct apconf *hconf, char *mac_addr)
{
  return denyacl_ap_command(hconf, DENYACL_DEL_COMMAND, mac_addr);
}

int disconnect_ap_command(struct apconf *hconf, char *mac_addr)
{
  if (denyacl_add_ap_command(hconf, mac_addr) < 0) {
    log_trace("denyacl_add_ap_command fail");
    return -1;
  }

  if (denyacl_del_ap_command(hconf, mac_addr) < 0) {
    log_trace("denyacl_del_ap_command fail");
    return -1;
  }

  return 0;
}

int find_ap_status(char *ap_answer, uint8_t *mac_addr, enum AP_CONNECTION_STATUS *status)
{
  UT_array *str_arr;
  char **ptr = NULL;

  utarray_new(str_arr, &ut_str_icd);

  if (split_string_array(ap_answer, 0x20, str_arr) > 1) {
    ptr = (char**) utarray_next(str_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      if (strstr(*ptr, AP_STA_CONNECTED) != NULL) {
        *status = AP_CONNECTED_STATUS;
      } else if (strstr(ap_answer, AP_STA_DISCONNECTED) != NULL) {
        *status = AP_DISCONNECTED_STATUS;
      } else {
        utarray_free(str_arr);
        return -1;
      }

      ptr = (char**) utarray_next(str_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (hwaddr_aton2(*ptr, mac_addr) != -1) {
          utarray_free(str_arr);
          return 0;
        }
      }
    }
  }

  utarray_free(str_arr);
  return -1;
}

void ap_sock_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  uint8_t mac_addr[ETH_ALEN];
  enum AP_CONNECTION_STATUS status;
  uint32_t bytes_available;
  char *rec_data, *trimmed;
  struct supervisor_context *context = (struct supervisor_context *) sock_ctx;
  ap_service_fn fn = (ap_service_fn) eloop_ctx;

  if (ioctl(sock, FIONREAD, &bytes_available) == -1) {
    log_err("ioctl");
    return;
  }

  rec_data = os_zalloc(bytes_available + 1);
  if (rec_data == NULL) {
    log_err("os_zalloc");
    return;
  }

  if (read_domain_data_s(sock, rec_data, bytes_available, context->hconfig.ctrl_interface_path, MSG_DONTWAIT) < 0) {
    log_trace("read_domain_data_s fail");
    os_free(rec_data);
    return;
  }

  if ((trimmed = rtrim(rec_data, NULL)) == NULL) {
    log_trace("rtrim fail");
    os_free(rec_data);
    return;
  }

  if (find_ap_status(trimmed, mac_addr, &status) > -1) {
    fn(context, mac_addr, status);
  }

  os_free(rec_data);
}

int register_ap_event(struct supervisor_context *context, void *ap_callback_fn)
{
  ssize_t cmd_len = (ssize_t) STRLEN(ATTACH_AP_COMMAND);

  if ((context->ap_sock = create_domain_client(NULL)) == -1) {
    log_debug("create_domain_client fail");
    return -1;
  }

  if (eloop_register_read_sock(context->ap_sock, ap_sock_handler, ap_callback_fn, (void *)context) ==  -1) {
    log_trace("eloop_register_read_sock fail");
    return -1;
  }

  log_trace("Sending command %s to socket_path=%s", ATTACH_AP_COMMAND, context->hconfig.ctrl_interface_path);
  if (write_domain_data_s(context->ap_sock, ATTACH_AP_COMMAND, cmd_len, context->hconfig.ctrl_interface_path) != cmd_len) {
    log_trace("write_domain_data_s fail");
    return -1;
  }

  return 0;
}

int run_ap(struct supervisor_context *context, bool exec_ap, void *ap_callback_fn)
{
  int res;
  if (!generate_vlan_conf(context->hconfig.vlan_file, context->hconfig.interface)) {
    log_trace("generate_vlan_conf fail");
    return -1;
  }

  if (!generate_hostapd_conf(&context->hconfig, &context->rconfig)) {
    unlink(context->hconfig.vlan_file);
    log_trace("generate_hostapd_conf fail");
    return -1;
  }

  if (exec_ap) {
    res = run_ap_process(&context->hconfig);
  } else {
    res = signal_ap_process(&context->hconfig);
  }

  if (!res && ping_ap_command(&context->hconfig) < 0) {
    log_trace("ping_ap_command fail");
    return -1;
  }

  if (register_ap_event(context, ap_callback_fn) < 0) {
    log_trace("register_ap_event fail");
    return -1;
  }

  return res;
}

bool close_ap(struct supervisor_context *context)
{
  if (context->ap_sock != -1) {
    close(context->ap_sock);
    context->ap_sock = -1;
  }

  return kill_ap_process();
}
