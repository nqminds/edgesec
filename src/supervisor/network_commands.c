/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the network commands.
 */
#include <libgen.h>

#include "mac_mapper.h"
#include "supervisor.h"
#include "sqlite_macconn_writer.h"
#include "network_commands.h"

#include "../ap/ap_config.h"
#include "../ap/ap_service.h"
#ifdef WITH_CRYPTO_SERVICE
#include "../crypt/crypt_service.h"
#endif
#include "../capture/capture_service.h"
#include "../dhcp/dhcp_service.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/net.h"
#include "../utils/base64.h"
#include "../utils/eloop.h"
#include "../firewall/firewall_service.h"

#define ANALYSER_FILTER_FORMAT                                                 \
  "\"ether dst " MACSTR " or ether src " MACSTR "\""

#ifdef WITH_CRYPTO_SERVICE
int save_to_crypt(struct crypt_context *crypt_ctx, struct mac_conn_info *info) {
  struct crypt_pair pair;

  pair.key = info->id;
  pair.value = info->pass;
  pair.value_size = info->pass_len;

  if (put_crypt_pair(crypt_ctx, &pair) < 0) {
    log_trace("put_crypt_pair fail");
    return -1;
  }

  return 0;
}
#endif

bool save_mac_mapper(struct supervisor_context *context, struct mac_conn conn) {
  if (!strlen(conn.info.id)) {
    generate_radom_uuid(conn.info.id);
  }

  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_error("put_mac_mapper fail");
    return false;
  }

#ifdef WITH_CRYPTO_SERVICE
  if (save_to_crypt(context->crypt_ctx, &(conn.info)) < 0) {
    log_error("save_to_crypt failure");
    return false;
  }

  // Reset the plain password array so that it is not stored
  // in plain form in the sqlite db
  conn.info.pass_len = 0;
  os_memset(conn.info.pass, 0, AP_SECRET_LEN);
#endif

  if (save_sqlite_macconn_entry(context->macconn_db, &conn) < 0) {
    log_error("upsert_sqlite_macconn_entry fail");
    return false;
  }

  return true;
}

void free_ticket(struct supervisor_context *context) {
  struct auth_ticket *ticket = context->ticket;
  if (ticket != NULL) {
    log_debug("Freeing ticket");
    os_free(ticket);
    context->ticket = NULL;
  }
}

void eloop_ticket_timeout_handler(void *eloop_ctx, void *user_ctx) {
  (void)eloop_ctx;

  struct supervisor_context *context = (struct supervisor_context *)user_ctx;
  log_debug("Auth ticket timeout, removing ticket");
  free_ticket(context);
}

int accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr,
                   int vlanid) {
  struct mac_conn conn;
  struct mac_conn_info info;
  struct vlan_conn vlan_conn;
  char mac_str[MACSTR_LEN];
  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  sprintf(mac_str, MACSTR, MAC2STR(mac_addr));
  log_debug("ACCEPT_MAC mac=%s with vlanid=%d", mac_str, vlanid);

  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_error("get_mac_mapper fail");
    return -1;
  }

  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  info.allow_connection = true;
  info.vlanid = vlanid;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (get_vlan_mapper(&context->vlan_mapper, conn.info.vlanid, &vlan_conn) <=
      0) {
    log_error("get_vlan_mapper fail");
    return -1;
  }

  os_memcpy(conn.info.ifname, vlan_conn.ifname, IF_NAMESIZE);
  if (!save_mac_mapper(context, conn)) {
    log_error("save_mac_mapper fail");
    return -1;
  }

  if (clear_dhcp_lease(mac_str, &context->dconfig) < 0) {
    log_error("clear_dhcp_lease fail");
    return -1;
  }

  if (check_sta_ap_command(&context->hconfig, mac_str) == 0) {
    if (disconnect_ap_command(&context->hconfig, mac_str) < 0) {
      log_error("disconnect_ap_command fail");
      return -1;
    }
  }

  return 0;
}

int deny_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr) {
  struct mac_conn conn;
  struct mac_conn_info info;
  char mac_str[MACSTR_LEN];
  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  sprintf(mac_str, MACSTR, MAC2STR(mac_addr));
  log_debug("DENY_MAC mac=%s", mac_str);

  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  info.allow_connection = false;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));
  if (!save_mac_mapper(context, conn)) {
    log_error("save_mac_mapper fail");
    return -1;
  }

  if (disconnect_ap_command(&context->hconfig, mac_str) < 0) {
    log_error("disconnect_ap_command fail");
    return -1;
  }

  return 0;
}

int add_nat_ip(struct supervisor_context *context, char *ip_addr) {
  if (validate_ipv4_string(ip_addr)) {
    if (fw_add_nat(context->fw_ctx, ip_addr) < 0) {
      log_error("fw_add_nat fail");
      return -1;
    }
  }

  return 0;
}

int remove_nat_ip(struct supervisor_context *context, char *ip_addr) {
  if (validate_ipv4_string(ip_addr)) {
    if (fw_remove_nat(context->fw_ctx, ip_addr) < 0) {
      log_error("fw_remove_nat fail");
      return -1;
    }
  }

  return 0;
}

int add_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr) {
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  log_debug("ADD_NAT mac=" MACSTR, MAC2STR(mac_addr));
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_error("get_mac_mapper fail");
    return -1;
  }

  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  info.nat = true;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (add_nat_ip(context, info.ip_addr) < 0) {
    log_error("add_nat_ip fail");
    return -1;
  }

  if (add_nat_ip(context, info.ip_sec_addr) < 0) {
    log_error("add_nat_ip fail");
    return -1;
  }

  if (!save_mac_mapper(context, conn)) {
    log_error("save_mac_mapper fail");
    return -1;
  }

  return 0;
}

int remove_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr) {
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  log_debug("REMOVE_NAT mac=" MACSTR, MAC2STR(mac_addr));
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_error("get_mac_mapper fail");
    return -1;
  }

  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  info.nat = false;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (remove_nat_ip(context, info.ip_addr) < 0) {
    log_error("remove_nat_ip fail");
    return -1;
  }

  if (remove_nat_ip(context, info.ip_sec_addr) < 0) {
    log_error("remove_nat_ip fail");
    return -1;
  }

  if (!save_mac_mapper(context, conn)) {
    log_error("save_mac_mapper fail");
    return -1;
  }

  return 0;
}

int assign_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr,
                   char *pass, int pass_len) {
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  log_debug("ASSIGN_PSK mac=" MACSTR ", pass_len=%d", MAC2STR(mac_addr),
            pass_len);

  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  os_memcpy(info.pass, pass, pass_len);
  info.pass_len = pass_len;
  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (!save_mac_mapper(context, conn)) {
    log_error("save_mac_mapper fail");
    return -1;
  }

  return 0;
}

int add_bridge_ip(struct supervisor_context *context, char *ip_addr_left,
                  char *ip_addr_right) {
  if (validate_ipv4_string(ip_addr_left) &&
      validate_ipv4_string(ip_addr_right)) {
    if (fw_add_bridge(context->fw_ctx, ip_addr_left, ip_addr_right) < 0) {
      log_error("fw_add_bridge fail");
      return -1;
    }
  }

  return 0;
}

int delete_bridge_ip(struct supervisor_context *context, char *ip_addr_left,
                     char *ip_addr_right) {
  if (validate_ipv4_string(ip_addr_left) &&
      validate_ipv4_string(ip_addr_right)) {
    if (fw_remove_bridge(context->fw_ctx, ip_addr_left, ip_addr_right) < 0) {
      log_error("fw_remove_bridge fail");
      return -1;
    }
  }

  return 0;
}

int add_bridge_mac_cmd(struct supervisor_context *context,
                       uint8_t *left_mac_addr, uint8_t *right_mac_addr) {
  struct mac_conn_info left_info, right_info;

  log_debug("ADD_BRIDGE left_mac=" MACSTR ", right_mac=" MACSTR,
            MAC2STR(left_mac_addr), MAC2STR(right_mac_addr));

  if (add_bridge_mac(context->bridge_list, left_mac_addr, right_mac_addr) >=
      0) {
    if (get_mac_mapper(&context->mac_mapper, left_mac_addr, &left_info) == 1 &&
        get_mac_mapper(&context->mac_mapper, right_mac_addr, &right_info) ==
            1) {
      if (add_bridge_ip(context, left_info.ip_addr, right_info.ip_addr) < 0) {
        log_error("add_bridge_ip fail");
        return -1;
      }
      if (add_bridge_ip(context, left_info.ip_addr, right_info.ip_sec_addr) <
          0) {
        log_error("add_bridge_ip fail");
        return -1;
      }
      if (add_bridge_ip(context, left_info.ip_sec_addr, right_info.ip_addr) <
          0) {
        log_error("add_bridge_ip fail");
        return -1;
      }
      if (add_bridge_ip(context, left_info.ip_sec_addr,
                        right_info.ip_sec_addr) < 0) {
        log_error("add_bridge_ip fail");
        return -1;
      }
    }
  } else {
    log_error("add_bridge_mac fail");
    return -1;
  }

  return 0;
}

int add_bridge_ip_cmd(struct supervisor_context *context, char *left_ip_addr,
                      char *right_ip_addr) {
  int ret;
  uint8_t left_mac_addr[ETHER_ADDR_LEN], right_mac_addr[ETHER_ADDR_LEN];

  ret = get_ip_mapper(&context->mac_mapper, left_ip_addr, left_mac_addr);
  if (ret < 0) {
    log_error("get_ip_mapper fail");
    return -1;
  } else if (!ret) {
    log_error("src MAC not found for bridge connection left_ip=%s, right_ip=%s",
              left_ip_addr, right_ip_addr);
    return -1;
  }

  ret = get_ip_mapper(&context->mac_mapper, right_ip_addr, right_mac_addr);

  if (ret < 0) {
    log_error("get_ip_mapper fail");
    return -1;
  } else if (!ret) {
    log_error("dst MAC not found for bridge connection left_ip=%s, right_ip=%s",
              left_ip_addr, right_ip_addr);
    return -1;
  }

  log_debug("ADD_BRIDGE left_ip=%s, right_ip=%s", left_ip_addr, right_ip_addr);

  if (check_bridge_exist(context->bridge_list, left_mac_addr, right_mac_addr) >
      0) {
    log_debug("Bridge between %s and %s already exists", left_ip_addr,
              right_ip_addr);
    return 0;
  }

  if (add_bridge_mac_cmd(context, left_mac_addr, right_mac_addr) < 0) {
    log_error("add_bridge_cmd fail");
    return -1;
  }

  return 0;
}

int remove_bridge_cmd(struct supervisor_context *context,
                      uint8_t *left_mac_addr, uint8_t *right_mac_addr) {
  struct mac_conn_info left_info, right_info;

  log_debug("REMOVE_BRIDGE left_mac=" MACSTR ", right_mac=" MACSTR,
            MAC2STR(left_mac_addr), MAC2STR(right_mac_addr));

  if (remove_bridge_mac(context->bridge_list, left_mac_addr, right_mac_addr) >=
      0) {
    if (get_mac_mapper(&context->mac_mapper, left_mac_addr, &left_info) == 1 &&
        get_mac_mapper(&context->mac_mapper, right_mac_addr, &right_info) ==
            1) {
      if (delete_bridge_ip(context, left_info.ip_addr, right_info.ip_addr) <
          0) {
        log_error("delete_bridge_ip fail");
        return -1;
      }
      if (delete_bridge_ip(context, left_info.ip_addr, right_info.ip_sec_addr) <
          0) {
        log_error("delete_bridge_ip fail");
        return -1;
      }
      if (delete_bridge_ip(context, left_info.ip_sec_addr, right_info.ip_addr) <
          0) {
        log_error("delete_bridge_ip fail");
        return -1;
      }
      if (delete_bridge_ip(context, left_info.ip_sec_addr,
                           right_info.ip_sec_addr) < 0) {
        log_error("delete_bridge_ip fail");
        return -1;
      }
    }
  } else {
    log_error("remove_bridge_mac fail");
    return -1;
  }

  return 0;
}

int clear_bridges_cmd(struct supervisor_context *context, uint8_t *mac_addr) {
  struct mac_conn *mac_list = NULL;
  int mac_list_len = get_mac_list(&context->mac_mapper, &mac_list);

  log_debug("CLEAR_BRIDGES mac=" MACSTR, MAC2STR(mac_addr));

  if (mac_list != NULL) {
    for (int count = 0; count < mac_list_len; count++) {
      struct mac_conn el = mac_list[count];
      remove_bridge_cmd(context, mac_addr, el.mac_addr);
    }

    os_free(mac_list);
  }

  return 0;
}

uint8_t *register_ticket_cmd(struct supervisor_context *context,
                             uint8_t *mac_addr, char *label, int vlanid) {
  log_debug("REGISTER_TICKET for mac=" MACSTR ", label=%s and vlanid=%d",
            MAC2STR(mac_addr), label, vlanid);

  if (context->ticket != NULL) {
    log_debug("Auth ticket is still active");
    return NULL;
  }

  context->ticket = os_zalloc(sizeof(struct auth_ticket));

  if (context->ticket == NULL) {
    log_errno("os_malloc");
    return NULL;
  }

  strcpy(context->ticket->device_label, label);
  context->ticket->vlanid = vlanid;
  context->ticket->passphrase_len = TICKET_PASSPHRASE_SIZE;

  if (os_get_random_number_s(context->ticket->passphrase,
                             context->ticket->passphrase_len) < 0) {
    log_error("os_get_random_number_s fail");
    os_free(context->ticket);
    return NULL;
  }

  if (eloop_register_timeout(context->eloop, TICKET_TIMEOUT, 0,
                             eloop_ticket_timeout_handler, NULL,
                             (void *)context) < 0) {
    log_error("eloop_register_timeout fail");
    os_free(context->ticket);
    return NULL;
  }

  return context->ticket->passphrase;
}

int clear_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr) {
  struct mac_conn conn;
  struct mac_conn_info info;

  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  log_debug("CLEAR_PSK for mac=" MACSTR, MAC2STR(mac_addr));

  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  os_memset(info.pass, 0, AP_SECRET_LEN);
  info.pass_len = 0;
  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (!save_mac_mapper(context, conn)) {
    log_error("save_mac_mapper fail");
    return -1;
  }

  return 0;
}
