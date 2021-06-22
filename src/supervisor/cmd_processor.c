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
#include "mac_mapper.h"
#include "network_commands.h"

#include "utils/os.h"
#include "utils/log.h"
#include "utils/utarray.h"
#include "utils/iptables.h"
#include "utils/domain.h"

bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len, UT_array *cmd_arr, char sep)
{
  if (domain_buffer == NULL || cmd_arr == NULL)
    return false;

  if (!domain_buffer_len)
    return false;

  char *cmd_line = os_malloc(domain_buffer_len + 1);
  if (cmd_line == NULL) {
    log_err("malloc");
    return false;
  }

  os_memcpy(cmd_line, domain_buffer, domain_buffer_len);
  cmd_line[domain_buffer_len] = '\0';

  // remove the end new line character
  if (split_string_array(rtrim(cmd_line, NULL), sep, cmd_arr) < 0) {
    log_trace("split_string_array fail");
    os_free(cmd_line);
    return false;
  }

  os_free(cmd_line);
  return true;
}

ssize_t process_ping_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr)
{
  (void) context; /* unused */
  (void) cmd_arr; /* unused */
  char *buf = "PONG";
  return write_domain_data(sock, buf, strlen(buf), client_addr);
}

ssize_t process_hostapd_ctrlif_cmd(int sock, char *client_addr, struct supervisor_context *context,
  UT_array *cmd_arr)
{
  (void) cmd_arr; /* unused */
  return write_domain_data(sock, context->hostapd_ctrl_if_path,
    strlen(context->hostapd_ctrl_if_path), client_addr);
}

ssize_t process_accept_mac_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  uint8_t addr[ETH_ALEN];
  int vlanid;

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      // vlanid
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        vlanid = (int) strtoul(*ptr, NULL, 10);
        if (errno != ERANGE && is_number(*ptr)) {
          if (accept_mac_cmd(context, addr, vlanid) < 0) {
            log_trace("accept_mac_cmd fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
          }
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

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      if (deny_mac_cmd(context, addr) < 0) {
        log_trace("deny_mac_cmd fail");
        return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
      }

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

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      if (add_nat_cmd(context, addr) < 0) {
        log_trace("add_nat_cmd fail");
        return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
      }

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

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      if (remove_nat_cmd(context, addr) < 0) {
        log_trace("remove_nat_cmd fail");
        return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
      }

      return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    } 
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_assign_psk_cmd(int sock, char *client_addr,
  struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  int pass_len;
  uint8_t addr[ETH_ALEN];

  // MAC address
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, addr) != -1) {
      // psk
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        pass_len = strlen(*ptr);
        if (pass_len <= AP_SECRET_LEN && pass_len) {
          if (assign_psk_cmd(context, addr, *ptr, pass_len) < 0) {
            log_trace("assign_psk_cmd fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
          }

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
      log_trace("GET_MAP for mac=" MACSTR, MAC2STR(addr));

      int ret = get_mac_mapper(&context->mac_mapper, addr, &info);

      if (ret == 1) {
        int line_size = snprintf(temp, 255, "%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%d,%d,%.*s\n",
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

ssize_t process_get_all_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr)
{
  (void) cmd_arr; /* unused */

  char temp[255], *reply_buf = NULL; 
  struct mac_conn *mac_list = NULL;
  int mac_list_len = get_mac_list(&context->mac_mapper, &mac_list);
  int total = 0;
  ssize_t bytes_sent;

  log_trace("GET_ALL");

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
  bool add = false;
  char dhcp_type[4];

  // add type
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    os_strlcpy(dhcp_type, *ptr, 4);
    log_trace("Received DHCP request with type=%s", dhcp_type);
    add = (strcmp(dhcp_type, "add") == 0 || strcmp(dhcp_type, "old") == 0);
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
          if (set_ip_cmd(context, addr, *ptr, add) < 0) {
            log_trace("set_ip_cmd fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);  
          }

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

  // MAC address source
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, left_addr) != -1) {
      // MAC address destination
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (hwaddr_aton2(*ptr, right_addr) != -1) {
          if (add_bridge_cmd(context, left_addr, right_addr) < 0) {
            log_trace("add_bridge_cmd fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);          
          }
          return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
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

  // MAC address source
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (hwaddr_aton2(*ptr, left_addr) != -1) {
      // MAC address destination
      ptr = (char**) utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (hwaddr_aton2(*ptr, right_addr) != -1) {
          if (remove_bridge_cmd(context, left_addr, right_addr) < 0) {
            log_trace("remove_bridge_cmd fail");
            return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
          }
          return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
        }
      }
    }
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_get_bridges_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr)
{
  (void) cmd_arr; /* unused */

  char temp[255], *reply_buf = NULL; 
  UT_array *tuple_list_arr;
  int total = 0;
  struct bridge_mac_tuple *p = NULL;
  ssize_t bytes_sent;
  if(get_all_bridge_edges(context->bridge_list, &tuple_list_arr) >= 0) {
    log_trace("GET_BRIDGES");
    while(p = (struct bridge_mac_tuple *) utarray_next(tuple_list_arr, p)) {
      int line_size = snprintf(temp, 255, MACSTR "," MACSTR "\n", MAC2STR(p->src_addr), MAC2STR(p->dst_addr));
      total += line_size + 1;
      if (reply_buf == NULL)
        reply_buf = os_zalloc(total);
      else
        reply_buf = os_realloc(reply_buf, total);
      strcat(reply_buf, temp);
    }

    utarray_free(tuple_list_arr);
    if (reply_buf) {
      bytes_sent = write_domain_data(sock, reply_buf, strlen(reply_buf), client_addr);
      os_free(reply_buf);
      return bytes_sent;
    } else
      return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_set_fingerprint_cmd(int sock, char *client_addr, struct supervisor_context *context, UT_array *cmd_arr)
{
  char **ptr = (char**) utarray_next(cmd_arr, NULL);
  char src_mac_addr[MACSTR_LEN];
  char dst_mac_addr[MACSTR_LEN];
  char protocol[MAX_PROTOCOL_NAME_LEN];

  // MAC address source
  ptr = (char**) utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    os_strlcpy(src_mac_addr, *ptr, MACSTR_LEN);
    // MAC address destination
    ptr = (char**) utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      os_strlcpy(dst_mac_addr, *ptr, MACSTR_LEN);
      ptr = (char**) utarray_next(cmd_arr, ptr);
      // Protocol
      if (ptr != NULL && *ptr != NULL) {
        os_strlcpy(protocol, *ptr, MAX_PROTOCOL_NAME_LEN);
        ptr = (char**) utarray_next(cmd_arr, ptr);
        // Fingerprint
        if (ptr != NULL && *ptr != NULL) {
          if ((set_fingerprint_cmd(context, src_mac_addr, protocol, *ptr) >= 0) &&
              (set_fingerprint_cmd(context, dst_mac_addr, protocol, *ptr) >= 0))
          {
            return write_domain_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
          }
        }
      }
    }
  }

  return write_domain_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

process_cmd_fn get_command_function(char *cmd)
{
  if (!strcmp(cmd, CMD_PING)) {
    return process_ping_cmd;
  } else if (!strcmp(cmd, CMD_HOSTAPD_CTRLIF)) {
    return process_hostapd_ctrlif_cmd;
  } else if (!strcmp(cmd, CMD_ACCEPT_MAC)) {
    return process_accept_mac_cmd;
  } else if (!strcmp(cmd, CMD_DENY_MAC)) {
    return process_deny_mac_cmd;
  } else if (!strcmp(cmd, CMD_ADD_NAT)) {
    return process_add_nat_cmd;
  } else if (!strcmp(cmd, CMD_REMOVE_NAT)) {
    return process_remove_nat_cmd;
  } else if (!strcmp(cmd, CMD_ASSIGN_PSK)) {
    return process_assign_psk_cmd;
  } else if (!strcmp(cmd, CMD_GET_MAP)) {
    return process_get_map_cmd;
  } else if (!strcmp(cmd, CMD_GET_ALL)) {
    return process_get_all_cmd;
  } else if (!strcmp(cmd, CMD_SET_IP)) {
    return process_set_ip_cmd;
  } else if (!strcmp(cmd, CMD_ADD_BRIDGE)) {
    return process_add_bridge_cmd;
  } else if (!strcmp(cmd, CMD_REMOVE_BRIDGE)) {
    return process_remove_bridge_cmd;
  } else if (!strcmp(cmd, CMD_GET_BRIDGES)) {
    return process_get_bridges_cmd;
  } else if (!strcmp(cmd, CMD_SET_FINGERPRINT)) {
    return process_set_fingerprint_cmd;
  } else {
    log_debug("unknown command");
  }

  return NULL;
}