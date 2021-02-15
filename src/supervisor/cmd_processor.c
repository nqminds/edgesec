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
 * @file cmd_processor.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the command processor functions.
 */

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "cmd_processor.h"
#include "domain_server.h"
#include "mac_mapper.h"

#include "utils/os.h"
#include "utils/log.h"
#include "utils/utarray.h"
#include "utils/iptables.h"


bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len, UT_array *cmd_arr)
{
  if (domain_buffer == NULL || cmd_arr == NULL)
    return false;

  if (!domain_buffer_len)
    return false;

  char *cmd_line = os_malloc(domain_buffer_len + 1);
  if (cmd_line == NULL) {
    log_err_ex("malloc");
  }

  os_memcpy(cmd_line, domain_buffer, domain_buffer_len);
  cmd_line[domain_buffer_len] = '\0';

  // remove the end new line character
  if (split_string_array(rtrim(cmd_line, NULL), CMD_DELIMITER, cmd_arr) == -1) {
    log_trace("split_string_array fail");
    os_free(cmd_line);
    return false;
  }

  os_free(cmd_line);
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

          if (get_mac_mapper(&context->mac_mapper, addr, &info) < 0) {
            log_trace("get_mac_mapper fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);          
          }

          memcpy(conn.mac_addr, addr, ETH_ALEN);
          info.vlanid = vlanid;
          conn.info = info;

          if (get_vlan_mapper(&context->vlan_mapper, conn.info.vlanid, conn.info.ifname) <= 0) {
            log_trace("get_vlan_mapper fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
          }

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
      if (get_mac_mapper(&context->mac_mapper, addr, &info) < 0) {
        log_trace("get_mac_mapper fail");
        return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
      }

      memcpy(conn.mac_addr, addr, ETH_ALEN);
      info.nat = true;
      conn.info = info;

      if (validate_ipv4_string(info.ip_addr)) {
        if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, info.ip_addr, ifname)) {
          log_trace("get_ifname_from_ip fail");
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
      if (get_mac_mapper(&context->mac_mapper, addr, &info) < 0) {
        log_trace("get_mac_mapper fail");
        return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
      }

      memcpy(conn.mac_addr, addr, ETH_ALEN);
      info.nat = false;
      conn.info = info;

      if (validate_ipv4_string(info.ip_addr)) {
        if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, info.ip_addr, ifname)) {
          log_trace("get_ifname_from_ip fail");
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
          if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, *ptr, ifname)) {
            log_trace("get_ifname_from_ip fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
          }

          if (get_mac_mapper(&context->mac_mapper, addr, &info) < 0) {
            log_trace("get_mac_mapper fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
          }

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
          log_trace("SET_IP type=%s mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%s if=%s", add_type, MAC2STR(conn.mac_addr), conn.info.ip_addr, conn.info.ifname);
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
  uint8_t left_addr[ETH_ALEN];
  uint8_t right_addr[ETH_ALEN];
  struct mac_conn_info left_info, right_info;

  // MAC address source
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, left_addr) != -1) {
      // MAC address destination
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (hwaddr_aton2(*ptr, right_addr) != -1) {
          if (add_bridge_mac(context->bridge_list, left_addr, right_addr) >= 0) {
            log_trace("ADD_BRIDGE left_mac=%02x:%02x:%02x:%02x:%02x:%02x right_mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(left_addr), MAC2STR(right_addr));
            if (get_mac_mapper(&context->mac_mapper, left_addr, &left_info) == 1 &&
                get_mac_mapper(&context->mac_mapper, right_addr, &right_info) == 1
            ) {
              if (validate_ipv4_string(left_info.ip_addr) && validate_ipv4_string(right_info.ip_addr)) {
                log_trace("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname);
                if (!add_bridge_rules(left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname)) {
                  log_trace("add_bridge_rules fail");
                  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
                }
              }
            }
            return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
          } else {
            log_trace("add_bridge_mac fail");
          }
        }
      }
    }
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_remove_bridge_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t left_addr[ETH_ALEN];
  uint8_t right_addr[ETH_ALEN];
  struct mac_conn_info left_info, right_info;

  // MAC address source
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, left_addr) != -1) {
      // MAC address destination
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (hwaddr_aton2(*ptr, right_addr) != -1) {
          if (remove_bridge_mac(context->bridge_list, left_addr, right_addr) >= 0) {
            // log_trace("REMOVE_BRIDGE left_mac=%02x:%02x:%02x:%02x:%02x:%02x right_mac=%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(left_addr), MAC2STR(right_addr));
            // if (get_mac_mapper(&context->mac_mapper, left_addr, &left_info) == 1 &&
            //     get_mac_mapper(&context->mac_mapper, right_addr, &right_info) == 1
            // ) {
            //   if (validate_ipv4_string(left_info.ip_addr) && validate_ipv4_string(right_info.ip_addr)) {
            //     log_trace("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname);
            //     if (!add_bridge_rules(left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname)) {
            //       log_trace("add_bridge_rules fail");
            //       return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
            //     }
            //   }
            // }
            // return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
          } else {
            log_trace("remove_bridge_mac fail");
          }
        }
      }
    }
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}
