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

#define PING_AP_COMMAND       "PING"
#define PING_AP_COMMAND_REPLY "PONG"
#define ATTACH_AP_COMMAND     "ATTACH"

typedef void (*ap_service_fn)(struct supervisor_context *context, char *data);

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
  if ((send_count = write_domain_data_s(sfd, cmd_str, strlen(cmd_str), socket_path)) != strlen(cmd_str)) {
    log_err("sendto");
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

// int subscribe_ap_command()
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

void ap_sock_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  struct supervisor_context *context = (struct supervisor_context *) sock_ctx;
  ap_service_fn fn = (ap_service_fn) eloop_ctx;
  fn(context, NULL);
}

int register_ap_event(struct supervisor_context *context, void *ap_callback_fn)
{
  if ((context->ap_sock = create_domain_client(NULL)) == -1) {
    log_debug("create_domain_client fail");
    return -1;
  }

  if (eloop_register_read_sock(context->ap_sock, ap_sock_handler, ap_callback_fn, (void *)context) ==  -1) {
    log_trace("eloop_register_read_sock fail");
    return -1;
  }

  log_trace("Sending to socket_path=%s", context->hconfig.ctrl_interface_path);
  if (write_domain_data_s(context->ap_sock, ATTACH_AP_COMMAND, STRLEN(ATTACH_AP_COMMAND), context->hconfig.ctrl_interface_path) != STRLEN(ATTACH_AP_COMMAND)) {
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
