/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the command processor functions.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/un.h>

#include "cmd_processor.h"
#include "mac_mapper.h"
#include "network_commands.h"
#ifdef WITH_CRYPTO_SERVICE
#include "crypt_commands.h"
#endif
#include "system_commands.h"

#include "utils/allocs.h"
#include "utils/base64.h"
#include "utils/log.h"
#include "utils/net.h"
#include "utils/os.h"
#include "utils/sockctl.h"

bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len,
                           UT_array *cmd_arr, char sep) {
  if (domain_buffer == NULL || cmd_arr == NULL)
    return false;

  if (!domain_buffer_len)
    return false;

  char *cmd_line = os_malloc(domain_buffer_len + 1);
  if (cmd_line == NULL) {
    log_errno("malloc");
    return false;
  }

  os_memcpy(cmd_line, domain_buffer, domain_buffer_len);
  cmd_line[domain_buffer_len] = '\0';

  // remove the end new line character
  if (split_string_array(rtrim(cmd_line, NULL), sep, cmd_arr) < 0) {
    log_error("split_string_array fail");
    os_free(cmd_line);
    return false;
  }

  os_free(cmd_line);
  return true;
}

int write_newline_socket_data(int sock, char *data,
                              struct client_address *client_addr) {
  char *msg;
  if ((msg = string_append_char(data, '\n')) == NULL) {
    log_error("string_append_char fail");
    return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
  }
  int ret = write_socket_data(sock, msg, strlen(msg), client_addr);
  os_free(msg);
  return ret;
}

ssize_t process_ping_cmd(int sock, struct client_address *client_addr,
                         struct supervisor_context *context,
                         UT_array *cmd_arr) {
  (void)context; /* unused */
  (void)cmd_arr; /* unused */
  char *reply = NULL;
  int ret;
  if ((reply = ping_cmd()) != NULL) {
    ret = write_socket_data(sock, reply, strlen(reply), client_addr);
    os_free(reply);
    return ret;
  }
  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_subscribe_events_cmd(int sock,
                                     struct client_address *client_addr,
                                     struct supervisor_context *context,
                                     UT_array *cmd_arr) {
  (void)cmd_arr; /* unused */

  if (subscribe_events_cmd(context, client_addr) < 0) {
    log_error("subscribe_events_cmd fail");
    return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
  }

  return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
}

ssize_t process_accept_mac_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t addr[ETHER_ADDR_LEN];
  int vlanid;

  // MAC address
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, addr) != -1) {
      // vlanid
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        errno = 0;
        vlanid = (int)strtoul(*ptr, NULL, 10);
        if (errno != ERANGE && is_number(*ptr)) {
          if (accept_mac_cmd(context, addr, vlanid) < 0) {
            log_error("accept_mac_cmd fail");
            return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                     client_addr);
          }
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_deny_mac_cmd(int sock, struct client_address *client_addr,
                             struct supervisor_context *context,
                             UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t addr[ETHER_ADDR_LEN];

  // MAC address
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, addr) != -1) {
      if (deny_mac_cmd(context, addr) < 0) {
        log_error("deny_mac_cmd fail");
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }

      return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_add_nat_cmd(int sock, struct client_address *client_addr,
                            struct supervisor_context *context,
                            UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t addr[ETHER_ADDR_LEN];

  // MAC address
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, addr) != -1) {
      if (add_nat_cmd(context, addr) < 0) {
        log_error("add_nat_cmd fail");
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }

      return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_remove_nat_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t addr[ETHER_ADDR_LEN];

  // MAC address
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, addr) != -1) {
      if (remove_nat_cmd(context, addr) < 0) {
        log_error("remove_nat_cmd fail");
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }

      return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_assign_psk_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  int pass_len;
  uint8_t addr[ETHER_ADDR_LEN];

  // MAC address
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, addr) != -1) {
      // psk
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        pass_len = strlen(*ptr);
        if (pass_len <= AP_SECRET_LEN && pass_len) {
          if (assign_psk_cmd(context, addr, *ptr, pass_len) < 0) {
            log_error("assign_psk_cmd fail");
            return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                     client_addr);
          }

          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_get_map_cmd(int sock, struct client_address *client_addr,
                            struct supervisor_context *context,
                            UT_array *cmd_arr) {
  char temp[255];
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t addr[ETHER_ADDR_LEN];
  struct mac_conn_info info;

  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  // MAC address
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, addr) != -1) {
      log_trace("GET_MAP for mac=" MACSTR, MAC2STR(addr));

      int ret = get_mac_mapper(&context->mac_mapper, addr, &info);

      if (ret == 1) {
        int line_size = snprintf(
            temp, 255,
            "%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%s,%d,%d,%s,%s,%d,%" PRIu64
            ",%d\n",
            (info.allow_connection) ? "a" : "d", MAC2STR(addr), info.ip_addr,
            info.ip_sec_addr, info.vlanid, (info.nat) ? 1 : 0, info.label,
            info.id, (info.pass_len) ? 1 : 0, info.join_timestamp,
            (int)info.status);
        return write_socket_data(sock, temp, line_size, client_addr);
      } else if (!ret) {
        return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_get_all_cmd(int sock, struct client_address *client_addr,
                            struct supervisor_context *context,
                            UT_array *cmd_arr) {
  (void)cmd_arr; /* unused */

  char temp[255], *reply_buf = NULL;
  struct mac_conn *mac_list = NULL;
  int mac_list_len = get_mac_list(&context->mac_mapper, &mac_list);
  int total = 0;
  ssize_t bytes_sent;

  log_trace("GET_ALL");

  if (mac_list != NULL) {
    for (int count = 0; count < mac_list_len; count++) {
      struct mac_conn el = mac_list[count];
      int line_size = snprintf(
          temp, 255,
          "%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%s,%d,%d,%s,%s,%d,%" PRIu64
          ",%d\n",
          (el.info.allow_connection) ? "a" : "d", MAC2STR(el.mac_addr),
          el.info.ip_addr, el.info.ip_sec_addr, el.info.vlanid,
          (el.info.nat) ? 1 : 0, el.info.label, el.info.id,
          (el.info.pass_len) ? 1 : 0, el.info.join_timestamp,
          (int)el.info.status);
      total += line_size + 1;
      if (reply_buf == NULL)
        reply_buf = sys_zalloc(total);
      else
        reply_buf = os_realloc(reply_buf, total);
      strcat(reply_buf, temp);
    }

    bytes_sent =
        write_socket_data(sock, reply_buf, strlen(reply_buf), client_addr);

    os_free(mac_list);
    os_free(reply_buf);
  } else {
    bytes_sent =
        write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
  }

  return bytes_sent;
}

ssize_t process_set_ip_cmd(int sock, struct client_address *client_addr,
                           struct supervisor_context *context,
                           UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t addr[ETHER_ADDR_LEN];
  char dhcp_type[4];
  enum DHCP_IP_TYPE ip_type = DHCP_IP_NONE;

  // add type
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    sys_strlcpy(dhcp_type, *ptr, 4);
    log_debug("Received DHCP request with type=%s", dhcp_type);
    if (strcmp(dhcp_type, "add") == 0) {
      ip_type = DHCP_IP_NEW;
    } else if (strcmp(dhcp_type, "old") == 0) {
      ip_type = DHCP_IP_OLD;
    } else if (strcmp(dhcp_type, "del") == 0) {
      ip_type = DHCP_IP_DEL;
    } else if (strcmp(dhcp_type, "arp") == 0) {
      ip_type = DHCP_IP_ARP;
      return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    } else {
      log_trace("Wrong type");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }
  } else {
    log_trace("Wrong type");
    return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
  }

  // MAC address
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, addr) != -1) {
      // ip
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (validate_ipv4_string(*ptr)) {
          if (set_ip_cmd(context, addr, *ptr, ip_type) < 0) {
            log_error("set_ip_cmd fail");
            return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                     client_addr);
          }

          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        } else {
          log_error("IP string, wrong format");
          return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                   client_addr);
        }
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_add_bridge_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t left_addr[ETHER_ADDR_LEN], right_addr[ETHER_ADDR_LEN];
  char left_ip[OS_INET_ADDRSTRLEN], right_ip[OS_INET_ADDRSTRLEN];

  // MAC address source
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, left_addr) != -1) {
      // MAC address destination
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (convert_ascii2mac(*ptr, right_addr) != -1) {
          if (add_bridge_mac_cmd(context, left_addr, right_addr) < 0) {
            log_error("add_bridge_cmd fail");
            return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                     client_addr);
          }
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    } else if (validate_ipv4_string(*ptr)) {
      sys_strlcpy(left_ip, *ptr, OS_INET_ADDRSTRLEN);

      // IP address destination
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (validate_ipv4_string(*ptr)) {
          sys_strlcpy(right_ip, *ptr, OS_INET_ADDRSTRLEN);

          if (add_bridge_ip_cmd(context, left_ip, right_ip) < 0) {
            log_error("add_bridge_cmd fail");
            return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                     client_addr);
          }
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_remove_bridge_cmd(int sock, struct client_address *client_addr,
                                  struct supervisor_context *context,
                                  UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t left_addr[ETHER_ADDR_LEN];
  uint8_t right_addr[ETHER_ADDR_LEN];

  // MAC address source
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, left_addr) != -1) {
      // MAC address destination
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (convert_ascii2mac(*ptr, right_addr) != -1) {
          if (remove_bridge_cmd(context, left_addr, right_addr) < 0) {
            log_error("remove_bridge_cmd fail");
            return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                     client_addr);
          }
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_clear_bridges_cmd(int sock, struct client_address *client_addr,
                                  struct supervisor_context *context,
                                  UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t left_addr[ETHER_ADDR_LEN];

  // MAC address source
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, left_addr) != -1) {
      if (clear_bridges_cmd(context, left_addr) < 0) {
        log_error("remove_bridge_cmd fail");
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }
      return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_get_bridges_cmd(int sock, struct client_address *client_addr,
                                struct supervisor_context *context,
                                UT_array *cmd_arr) {
  (void)cmd_arr; /* unused */

  char temp[255], *reply_buf = NULL;
  UT_array *tuple_list_arr;
  int total = 0;
  struct bridge_mac_tuple *p = NULL;
  ssize_t bytes_sent;
  if (get_all_bridge_edges(context->bridge_list, &tuple_list_arr) >= 0) {
    log_trace("GET_BRIDGES");
    while ((p = (struct bridge_mac_tuple *)utarray_next(tuple_list_arr, p)) !=
           NULL) {
      int line_size = snprintf(temp, 255, MACSTR "," MACSTR "\n",
                               MAC2STR(p->src_addr), MAC2STR(p->dst_addr));
      total += line_size + 1;
      if (reply_buf == NULL)
        reply_buf = sys_zalloc(total);
      else
        reply_buf = os_realloc(reply_buf, total);
      strcat(reply_buf, temp);
    }

    utarray_free(tuple_list_arr);
    if (reply_buf) {
      bytes_sent =
          write_socket_data(sock, reply_buf, strlen(reply_buf), client_addr);
      os_free(reply_buf);
      return bytes_sent;
    } else
      return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_register_ticket_cmd(int sock,
                                    struct client_address *client_addr,
                                    struct supervisor_context *context,
                                    UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t mac_addr[ETHER_ADDR_LEN];
  int vlanid;
  char label[MAX_DEVICE_LABEL_SIZE];
  char *passphrase;

  // MAC address of issuer
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, mac_addr) != -1) {
      // Device label
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (os_strnlen_s(*ptr, MAX_DEVICE_LABEL_SIZE) < MAX_DEVICE_LABEL_SIZE) {
          sys_strlcpy(label, *ptr, MAX_DEVICE_LABEL_SIZE);

          // VLAN ID
          ptr = (char **)utarray_next(cmd_arr, ptr);
          if (ptr != NULL && *ptr != NULL) {
            errno = 0;
            vlanid = (int)strtoul(*ptr, NULL, 10);
            if (errno != ERANGE && is_number(*ptr)) {
              passphrase =
                  (char *)register_ticket_cmd(context, mac_addr, label, vlanid);

              if (passphrase != NULL) {
                return write_newline_socket_data(sock, passphrase, client_addr);
              } else {
                return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                         client_addr);
              }
            }
          }
        }
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_clear_psk_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  uint8_t mac_addr[ETHER_ADDR_LEN];

  // MAC address of issuer
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if (convert_ascii2mac(*ptr, mac_addr) != -1) {
      if (clear_psk_cmd(context, mac_addr) >= 0) {
        return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY), client_addr);
      }
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

#ifdef WITH_CRYPTO_SERVICE
ssize_t process_put_crypt_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *key = NULL;
  char *value = NULL, *trimmed;

  // key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((key = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // value
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      if ((value = os_strdup(*ptr)) == NULL) {
        log_errno("os_strdup");
        os_free(key);
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }

      trimmed = rtrim(value, NULL);
      if (strlen(trimmed)) {
        if (!put_crypt_cmd(context, key, trimmed)) {
          os_free(key);
          os_free(value);
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
      os_free(value);
    }
    os_free(key);
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_get_crypt_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *key = NULL, *value = NULL, *trimmed;
  ssize_t ret = -1;

  // key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((key = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    trimmed = rtrim(key, NULL);
    if (strlen(trimmed)) {
      if (!get_crypt_cmd(context, key, &value)) {
        os_free(key);
        ret = write_newline_socket_data(sock, value, client_addr);
        os_free(value);
        return ret;
      }
    }
  }
  os_free(key);

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_gen_randkey_cmd(int sock, struct client_address *client_addr,
                                struct supervisor_context *context,
                                UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *keyid = NULL;
  uint8_t key_size;

  // key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((keyid = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // key size
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      errno = 0;
      key_size = (uint8_t)strtoul(*ptr, NULL, 10);
      if (errno != ERANGE && is_number(*ptr)) {
        if (!gen_randkey_cmd(context, keyid, key_size)) {
          os_free(keyid);
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    }
    os_free(keyid);
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_gen_privkey_cmd(int sock, struct client_address *client_addr,
                                struct supervisor_context *context,
                                UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *keyid = NULL;
  uint8_t key_size;

  // key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((keyid = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // key size
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      errno = 0;
      key_size = (uint8_t)strtoul(*ptr, NULL, 10);
      if (errno != ERANGE && is_number(*ptr)) {
        if (!gen_privkey_cmd(context, keyid, key_size)) {
          os_free(keyid);
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    }
    os_free(keyid);
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_gen_pubkey_cmd(int sock, struct client_address *client_addr,
                               struct supervisor_context *context,
                               UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *pubid = NULL;

  // public key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((pubid = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // private key id
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      if (strlen(*ptr)) {
        if (!gen_pubkey_cmd(context, pubid, *ptr)) {
          os_free(pubid);
          return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                   client_addr);
        }
      }
    }
    os_free(pubid);
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_gen_cert_cmd(int sock, struct client_address *client_addr,
                             struct supervisor_context *context,
                             UT_array *cmd_arr) {
  struct certificate_meta meta;
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *certid = NULL;
  char *keyid = NULL;

  os_memset(&meta, 0, sizeof(struct certificate_meta));
  meta.not_before = 0;
  meta.not_after = 31536000L;
  strcpy(meta.c, "IE");
  strcpy(meta.o, "nqmcyber");
  strcpy(meta.ou, "R&D");

  // cert id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((certid = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // private key id
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      if ((keyid = os_strdup(*ptr)) == NULL) {
        log_errno("os_strdup");
        os_free(certid);
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }

      // common name
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (strlen(*ptr)) {
          strcpy(meta.cn, *ptr);
          if (!gen_cert_cmd(context, certid, keyid, &meta)) {
            os_free(keyid);
            os_free(certid);
            return write_socket_data(sock, OK_REPLY, strlen(OK_REPLY),
                                     client_addr);
          }
        }
      }
      os_free(keyid);
    }
    os_free(certid);
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_encrypt_blob_cmd(int sock, struct client_address *client_addr,
                                 struct supervisor_context *context,
                                 UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *keyid = NULL;
  char *ivid = NULL;
  char *encrypted = NULL;
  int ret;

  // key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((keyid = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // iv id
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      if ((ivid = os_strdup(*ptr)) == NULL) {
        log_errno("os_strdup");
        os_free(keyid);
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }

      // blob
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (strlen(*ptr)) {
          if ((encrypted = encrypt_blob_cmd(context, keyid, ivid, *ptr)) !=
              NULL) {
            ret = write_newline_socket_data(sock, encrypted, client_addr);

            os_free(ivid);
            os_free(keyid);
            os_free(encrypted);
            return ret;
          }
        }
      }
      os_free(ivid);
      os_free(keyid);
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_decrypt_blob_cmd(int sock, struct client_address *client_addr,
                                 struct supervisor_context *context,
                                 UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *keyid = NULL;
  char *ivid = NULL;
  char *decrypted = NULL;
  int ret;

  // key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((keyid = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // iv id
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      if ((ivid = os_strdup(*ptr)) == NULL) {
        log_errno("os_strdup");
        os_free(keyid);
        return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                                 client_addr);
      }

      // blob
      ptr = (char **)utarray_next(cmd_arr, ptr);
      if (ptr != NULL && *ptr != NULL) {
        if (strlen(*ptr)) {
          if ((decrypted = decrypt_blob_cmd(context, keyid, ivid, *ptr)) !=
              NULL) {
            ret = write_newline_socket_data(sock, decrypted, client_addr);
            os_free(keyid);
            os_free(ivid);
            os_free(decrypted);
            return ret;
          }
        }
      }
      os_free(keyid);
      os_free(ivid);
    }
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}

ssize_t process_sign_blob_cmd(int sock, struct client_address *client_addr,
                              struct supervisor_context *context,
                              UT_array *cmd_arr) {
  char **ptr = (char **)utarray_next(cmd_arr, NULL);
  char *keyid = NULL;
  char *signed_str = NULL;
  int ret;

  // key id
  ptr = (char **)utarray_next(cmd_arr, ptr);
  if (ptr != NULL && *ptr != NULL) {
    if ((keyid = os_strdup(*ptr)) == NULL) {
      log_errno("os_strdup");
      return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY),
                               client_addr);
    }

    // blob
    ptr = (char **)utarray_next(cmd_arr, ptr);
    if (ptr != NULL && *ptr != NULL) {
      if (strlen(*ptr)) {
        if ((signed_str = sign_blob_cmd(context, keyid, *ptr)) != NULL) {
          ret = write_newline_socket_data(sock, signed_str, client_addr);
          os_free(keyid);
          os_free(signed_str);
          return ret;
        }
      }
    }
    os_free(keyid);
  }

  return write_socket_data(sock, FAIL_REPLY, strlen(FAIL_REPLY), client_addr);
}
#endif

process_cmd_fn get_command_function(char *cmd) {
  if (!strcmp(cmd, CMD_PING)) {
    return process_ping_cmd;
  } else if (!strcmp(cmd, CMD_SUBSCRIBE_EVENTS)) {
    return process_subscribe_events_cmd;
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
  } else if (!strcmp(cmd, CMD_CLEAR_BRIDGES)) {
    return process_clear_bridges_cmd;
  } else if (!strcmp(cmd, CMD_GET_BRIDGES)) {
    return process_get_bridges_cmd;
  } else if (!strcmp(cmd, CMD_REGISTER_TICKET)) {
    return process_register_ticket_cmd;
  } else if (!strcmp(cmd, CMD_CLEAR_PSK)) {
    return process_clear_psk_cmd;
  }
#ifdef WITH_CRYPTO_SERVICE
  else if (!strcmp(cmd, CMD_PUT_CRYPT)) {
    return process_put_crypt_cmd;
  } else if (!strcmp(cmd, CMD_GET_CRYPT)) {
    return process_get_crypt_cmd;
  } else if (!strcmp(cmd, CMD_GEN_RANDKEY)) {
    return process_gen_randkey_cmd;
  } else if (!strcmp(cmd, CMD_GEN_PRIVKEY)) {
    return process_gen_privkey_cmd;
  } else if (!strcmp(cmd, CMD_GEN_PUBKEY)) {
    return process_gen_pubkey_cmd;
  } else if (!strcmp(cmd, CMD_GEN_CERT)) {
    return process_gen_cert_cmd;
  } else if (!strcmp(cmd, CMD_ENCRYPT_BLOB)) {
    return process_encrypt_blob_cmd;
  } else if (!strcmp(cmd, CMD_DECRYPT_BLOB)) {
    return process_decrypt_blob_cmd;
  } else if (!strcmp(cmd, CMD_SIGN_BLOB)) {
    return process_sign_blob_cmd;
  }
#endif
  else {
    log_trace("unknown command");
  }

  return NULL;
}
