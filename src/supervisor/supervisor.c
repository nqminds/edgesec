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
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>


#include "utils/log.h"
#include "utils/os.h"
#include "utils/eloop.h"
#include "utils/utarray.h"
#include "utils/iptables.h"

#include "supervisor.h"
#include "domain_server.h"
#include "cmd_processor.h"

#define OK_REPLY    "OK"
#define FAIL_REPLY  "FAIL"

bool get_bridge_ifname(hmap_if_conn **if_mapper, UT_array *config_ifinfo_array, char *ip, char *ifname)
{
  in_addr_t subnet_addr;

  if (find_subnet_address(config_ifinfo_array, ip, &subnet_addr) != 0) {
    log_trace("find_subnet_address fail");
    return false;
  }

  if (!get_if_mapper(if_mapper, subnet_addr, ifname)) {
    log_trace("get_if_mapper fail");
    return false;
  }

  return true;
}

ssize_t process_ping_cmd(int sock, char *client_addr)
{
  char *buf = "PONG";
  return write_domain_data(sock, buf, strlen(buf), client_addr);
}

ssize_t process_hostapd_ctrlif_cmd(int sock, char *client_addr,
  struct supervisor_context *context)
{
  return write_domain_data(sock, context->hostapd_ctrl_if_path,
    strlen(context->hostapd_ctrl_if_path), client_addr);
}

ssize_t process_accept_mac_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  int vlanid;
  struct mac_conn conn;
  struct mac_conn_info info = {.nat = false, .pass_len = 0};

  os_memset(info.ip_addr, 0x0, IP_LEN);

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      // vlanid
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        vlanid = (int) strtoul(*ptr, NULL, 10);
        if (errno != ERANGE && is_number(*ptr)) {
          log_trace("ACCEPT_MAC mac=%02x:%02x:%02x:%02x:%02x:%02x with vlanid=%d", MAC2STR(addr), vlanid);

          get_mac_mapper(&context->mac_mapper, addr, &info);
          memcpy(conn.mac_addr, addr, ETH_ALEN);
          info.vlanid = vlanid;
          conn.info = info;

          if (put_mac_mapper(&context->mac_mapper, conn))
            return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
        }
      }
    } 
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_deny_mac_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  struct mac_conn conn;
  struct mac_conn_info info = {.vlanid = 0, .nat = false, .pass_len = 0};

  os_memset(info.ip_addr, 0x0, IP_LEN);

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      log_trace("DENY_MAC mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(addr));
      get_mac_mapper(&context->mac_mapper, addr, &info);
      memcpy(conn.mac_addr, addr, ETH_ALEN);
      info.allow_connection = false;
      conn.info = info;
      if (put_mac_mapper(&context->mac_mapper, conn))
        return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    } 
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_add_nat_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info info = {.vlanid = 0, .allow_connection = false, .pass_len = 0};

  os_memset(info.ip_addr, 0x0, IP_LEN);

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      log_trace("ADD_NAT mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(addr));
      get_mac_mapper(&context->mac_mapper, addr, &info);
      memcpy(conn.mac_addr, addr, ETH_ALEN);
      info.nat = true;
      conn.info = info;

      if (strlen(info.ip_addr)) {
        if (!get_bridge_ifname(&context->if_mapper, context->config_ifinfo_array, info.ip_addr, ifname)) {
          log_trace("get_bridge_ifname fail");
          return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
        }

        if (!add_nat_rules(info.ip_addr, ifname, context->nat_interface)) {
          log_trace("add_nat_rules fail");
          return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
        }
      }

      if (put_mac_mapper(&context->mac_mapper, conn))
        return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    } 
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_remove_nat_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info info = {.vlanid = 0, .nat = false, .allow_connection = false, .pass_len = 0};

  os_memset(info.ip_addr, 0x0, IP_LEN);

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      log_trace("REMOVE_NAT mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(addr));
      get_mac_mapper(&context->mac_mapper, addr, &info);
      memcpy(conn.mac_addr, addr, ETH_ALEN);
      info.nat = false;
      conn.info = info;

      if (strlen(info.ip_addr)) {
        if (!get_bridge_ifname(&context->if_mapper, context->config_ifinfo_array, info.ip_addr, ifname)) {
          log_trace("get_bridge_ifname fail");
          return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
        }

        if (!delete_nat_rules(info.ip_addr, ifname, context->nat_interface)) {
          log_trace("delete_nat_rules fail");
          return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
        }
      }

      if (put_mac_mapper(&context->mac_mapper, conn))
        return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    } 
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_assign_psk_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  struct mac_conn conn;
  struct mac_conn_info info = {.vlanid = 0, .nat = false, .allow_connection = false, .pass_len = 0};

  os_memset(info.ip_addr, 0x0, IP_LEN);

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      // psk
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (strlen(*ptr) <= HOSTAPD_AP_SECRET_LEN) {
          log_trace("ASSIGN_PSK mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(addr));

          get_mac_mapper(&context->mac_mapper, addr, &info);
          memcpy(info.pass, *ptr, strlen(*ptr));
          info.pass_len = strlen(*ptr);
          memcpy(conn.mac_addr, addr, ETH_ALEN);
          conn.info = info;

          if (put_mac_mapper(&context->mac_mapper, conn))
            return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
        }
      }
    } 
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_get_map_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char temp[255];
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  struct mac_conn_info info;

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      log_trace("GET_MAP for mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(addr));

      int ret = get_mac_mapper(&context->mac_mapper, addr, &info);

      if (ret == 1) {
        int line_size = snprintf(temp, 255, "%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%d,%d,%.*s",
          (info.allow_connection) ? "a" : "d", MAC2STR(addr), info.ip_addr, info.vlanid, (info.nat) ? 1 : 0,
          (int) info.pass_len, info.pass);
        return write_domain_data(sock, temp, line_size, client_addr);
      } else if (!ret) {
        return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
      }
    } 
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_get_all_cmd(int sock, char *client_addr, struct supervisor_context *context)
{
  char temp[255], *reply_buf = NULL; 
  struct mac_conn *mac_list = NULL;
  int mac_list_len = get_mac_list(&context->mac_mapper, &mac_list);
  int total = 0;
  ssize_t bytes_sent;

  for (int count = 0; count < mac_list_len; count ++) {
    struct mac_conn el = mac_list[count];
    int line_size = snprintf(temp, 255, "%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%d,%d,%.*s\n",
      (el.info.allow_connection) ? "a" : "d", MAC2STR(el.mac_addr), el.info.ip_addr, el.info.vlanid,
      (el.info.nat) ? 1 : 0, (int) el.info.pass_len, el.info.pass);
    total += line_size + 1;
    if (reply_buf == NULL)
      reply_buf = os_zalloc(total);
    else
      reply_buf = os_realloc(reply_buf, total);
    strcat(reply_buf, temp);
  }

  if (mac_list != NULL) {
    bytes_sent = write_domain_data(sock, reply_buf, strlen(reply_buf), client_addr);

    os_free(mac_list);
    os_free(reply_buf);
  } else {
    bytes_sent = write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
  }

  return bytes_sent;
}

ssize_t process_set_ip_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  char add_type[4];
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info info = {.vlanid = 0, .nat = false, .allow_connection = false, .pass_len = 0};

  os_memset(info.ip_addr, 0x0, IP_LEN);

  // add type
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    strncpy(add_type, *ptr, 4);
  } else {
    log_trace("Wrong type");
    return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
  }

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      // ip
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (validate_ipv4_string(*ptr)) {
          log_trace("SET_IP type=%s mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%s", add_type, MAC2STR(addr), *ptr);

          if (!get_bridge_ifname(&context->if_mapper, context->config_ifinfo_array, *ptr, ifname)) {
            log_trace("get_bridge_ifname fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
          }

          get_mac_mapper(&context->mac_mapper, addr, &info);

          if (!strcmp(add_type, "add") || !strcmp(add_type, "old")) {
            strcpy(info.ip_addr, *ptr);
            if (info.nat) {
              if (!add_nat_rules(info.ip_addr, ifname, context->nat_interface)) {
                log_trace("add_nat_rules fail");
                return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
              }
            }
          } else {
            // Clear the IP address
            os_memset(info.ip_addr, 0x0, IP_LEN);
            if (info.nat) {
              if (!delete_nat_rules(*ptr, ifname, context->nat_interface)) {
                log_trace("delete_nat_rules fail");
                return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
              }
            }
          }

          memcpy(conn.mac_addr, addr, ETH_ALEN);
          conn.info = info;

          if (put_mac_mapper(&context->mac_mapper, conn))
            return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
        } else {
          log_trace("IP string, wrong format");
          return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
        }
      }
    }
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_add_bridge_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  uint8_t addr_bridge[ETH_ALEN];
  struct mac_conn conn;
  struct mac_conn_info info = {.vlanid = 0, .nat = false, .allow_connection = false, .pass_len = 0};

  os_memset(info.ip_addr, 0x0, IP_LEN);

  // // MAC address
  // ptr = (char**) utarray_next(cmd_arr, ptr);
  // if (ptr != NULL && *ptr != NULL) {
  //   if (hwaddr_aton2(*ptr, addr) != -1) {
  //     // vlanid
  //     ptr = (char**) utarray_next(cmd_arr, ptr);
  //     if (ptr != NULL && *ptr != NULL) {
  //       vlanid = (int) strtoul(*ptr, NULL, 10);
  //       if (errno != ERANGE && is_number(*ptr)) {
  //         log_trace("ACCEPT_MAC mac=%02x:%02x:%02x:%02x:%02x:%02x with vlanid=%d", MAC2STR(addr), vlanid);

  //         get_mac_mapper(&context->mac_mapper, addr, &info);
  //         memcpy(conn.mac_addr, addr, ETH_ALEN);
  //         info.vlanid = vlanid;
  //         conn.info = info;

  //         if (put_mac_mapper(&context->mac_mapper, conn))
  //           return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
  //       }
  //     }
  //   } 
  // }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_remove_bridge_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

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
