/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file network_commands.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the network commands.
 */
#include <libgen.h>

#include "mac_mapper.h"
#include "supervisor.h"
#include "sqlite_fingerprint_writer.h"
#include "sqlite_macconn_writer.h"
#include "network_commands.h"

#include "../ap/ap_config.h"
#include "../ap/ap_service.h"
#include "../crypt/crypt_service.h"
#include "../capture/capture_service.h"
#include "../dhcp/dhcp_service.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/net.h"
#include "../utils/base64.h"
#include "../utils/eloop.h"
#include "../utils/iptables.h"

#define ANALYSER_FILTER_FORMAT "\"ether dst " MACSTR " or ether src " MACSTR"\""

bool save_mac_mapper(struct supervisor_context *context, struct mac_conn conn)
{
  struct crypt_pair pair;

  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_trace("put_mac_mapper fail");
    return false;
  }

  if (save_sqlite_macconn_entry(context->macconn_db, &conn) < 0) {
    log_trace("upsert_sqlite_macconn_entry fail");
    return false;
  }

  pair.key = conn.info.id;
  pair.value = conn.info.pass;
  pair.value_size = conn.info.pass_len;

  if (put_crypt_pair(context->crypt_ctx, &pair) < 0) {
    log_trace("put_crypt_pair fail");
    return false;
  }

  return true;
}

void free_ticket(struct supervisor_context *context)
{
  struct auth_ticket *ticket = context->ticket;
  if (ticket != NULL) {
    log_trace("Freeing ticket");
    os_free(ticket);
    context->ticket = NULL;
  }
}

void eloop_ticket_timeout_handler(void *eloop_ctx, void *user_ctx)
{
  (void) eloop_ctx;

  struct supervisor_context *context = (struct supervisor_context *) user_ctx;
  log_trace("Auth ticket timeout, removing ticket");
  free_ticket(context);
}

int accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr, int vlanid)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  struct vlan_conn vlan_conn;
  char mac_str[MACSTR_LEN];
  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  sprintf(mac_str, MACSTR, MAC2STR(mac_addr));
  log_trace("ACCEPT_MAC mac=%s with vlanid=%d", mac_str, vlanid);

  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.allow_connection = true;
  info.vlanid = vlanid;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (get_vlan_mapper(&context->vlan_mapper, conn.info.vlanid, &vlan_conn) <= 0) {
    log_trace("get_vlan_mapper fail");
    return -1;
  }

  os_memcpy(conn.info.ifname, vlan_conn.ifname, IFNAMSIZ);
  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    return -1;
  }

  if (clear_dhcp_lease(mac_str, &context->dconfig) < 0) {
    log_trace("clear_dhcp_lease fail");
    return -1;
  }

  if (check_sta_ap_command(&context->hconfig, mac_str) == 0) {
    if (disconnect_ap_command(&context->hconfig, mac_str) < 0) {
      log_trace("disconnect_ap_command fail");
      return -1;
    }
  }

  return 0;
}

int deny_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  char mac_str[MACSTR_LEN];
  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  sprintf(mac_str, MACSTR, MAC2STR(mac_addr));
  log_trace("DENY_MAC mac=%s", mac_str);

  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.allow_connection = false;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));
  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    return -1;
  }

  if (disconnect_ap_command(&context->hconfig, mac_str) < 0) {
    log_trace("disconnect_ap_command fail");
    return -1;
  }

  return 0;
}

int add_nat_ip(struct supervisor_context *context, char *ip_addr)
{
  char ifname[IFNAMSIZ];

  if (validate_ipv4_string(ip_addr)) {
    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr, ifname)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }
    log_trace("Adding iptable rule for ip=%s if=%s", ip_addr, ifname);
    if (!iptables_add_nat(context->iptables_ctx, ip_addr, ifname, context->nat_interface)) {
      log_trace("iptables_add_nat fail");
      return -1;
    }
  }

  return 0;
}

int remove_nat_ip(struct supervisor_context *context, char *ip_addr)
{
  char ifname[IFNAMSIZ];

  if (validate_ipv4_string(ip_addr)) {
    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr, ifname)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }
    log_trace("Removing iptable rule for ip=%s if=%s", ip_addr, ifname);
    if (!iptables_delete_nat(context->iptables_ctx, ip_addr, ifname, context->nat_interface)) {
      log_trace("iptables_delete_nat fail");
      return -1;
    }
  }

  return 0;
}

int add_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  log_trace("ADD_NAT mac=" MACSTR, MAC2STR(mac_addr));
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.nat = true;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (add_nat_ip(context, info.ip_addr) < 0) {
    log_trace("add_nat_ip fail");
    return -1;
  }

  if (add_nat_ip(context, info.ip_sec_addr) < 0) {
    log_trace("add_nat_ip fail");
    return -1;
  }

  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    return -1;
  }

  return 0;
}

int remove_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  log_trace("REMOVE_NAT mac=" MACSTR, MAC2STR(mac_addr));
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.nat = false;
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (remove_nat_ip(context, info.ip_addr) < 0) {
    log_trace("remove_nat_ip fail");
    return -1;
  }

  if (remove_nat_ip(context, info.ip_sec_addr) < 0) {
    log_trace("remove_nat_ip fail");
    return -1;
  }

  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    return -1;
  }

  return 0;
}

int assign_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *pass, int pass_len)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  log_trace("ASSIGN_PSK mac=" MACSTR ", pass_len=%d", MAC2STR(mac_addr), pass_len);

  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  os_memcpy(info.pass, pass, pass_len);
  info.pass_len = pass_len;
  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    return -1;
  }

  return 0;
}

int add_bridge_ip(struct supervisor_context *context, char *ip_addr_left, char *ip_addr_right)
{
  char ifname_left[IFNAMSIZ], ifname_right[IFNAMSIZ];

  if (validate_ipv4_string(ip_addr_left) && validate_ipv4_string(ip_addr_right)) {
    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_left, ifname_left)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }

    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_right, ifname_right)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }

    log_trace("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", ip_addr_left, ifname_left, ip_addr_right, ifname_right);
    if (!iptables_add_bridge(context->iptables_ctx, ip_addr_left, ifname_left, ip_addr_right, ifname_right)) {
      log_trace("iptables_add_bridge fail");
      return -1;
    }
  }

  return 0;
}

int delete_bridge_ip(struct supervisor_context *context, char *ip_addr_left, char *ip_addr_right)
{
  char ifname_left[IFNAMSIZ], ifname_right[IFNAMSIZ];

  if (validate_ipv4_string(ip_addr_left) && validate_ipv4_string(ip_addr_right)) {
    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_left, ifname_left)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }

    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_right, ifname_right)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }

    log_trace("Removing iptable rule for sip=%s sif=%s dip=%s dif=%s", ip_addr_left, ifname_left, ip_addr_right, ifname_right);
    if (!iptables_delete_bridge(context->iptables_ctx, ip_addr_left, ifname_left, ip_addr_right, ifname_right)) {
      log_trace("iptables_add_bridge fail");
      return -1;
    }
  }

  return 0;
}

int add_bridge_mac_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  struct mac_conn_info left_info, right_info;

  log_trace("ADD_BRIDGE left_mac=" MACSTR ", right_mac="MACSTR, MAC2STR(left_mac_addr), MAC2STR(right_mac_addr));

  if (add_bridge_mac(context->bridge_list, left_mac_addr, right_mac_addr) >= 0) {
    if (get_mac_mapper(&context->mac_mapper, left_mac_addr, &left_info) == 1 &&
        get_mac_mapper(&context->mac_mapper, right_mac_addr, &right_info) == 1
    ) {
      if (add_bridge_ip(context, left_info.ip_addr, right_info.ip_addr) < 0) {
        log_trace("add_bridge_ip fail");
        return -1;
      }
      if (add_bridge_ip(context, left_info.ip_addr, right_info.ip_sec_addr) < 0) {
        log_trace("add_bridge_ip fail");
        return -1;
      }
      if (add_bridge_ip(context, left_info.ip_sec_addr, right_info.ip_addr) < 0) {
        log_trace("add_bridge_ip fail");
        return -1;
      }
      if (add_bridge_ip(context, left_info.ip_sec_addr, right_info.ip_sec_addr) < 0) {
        log_trace("add_bridge_ip fail");
        return -1;
      }
    }
  } else {
    log_trace("add_bridge_mac fail");
    return -1;
  }

  return 0;
}

int add_bridge_ip_cmd(struct supervisor_context *context, char *left_ip_addr, char *right_ip_addr)
{
  int ret;
  uint8_t left_mac_addr[ETH_ALEN], right_mac_addr[ETH_ALEN];

  ret = get_ip_mapper(&context->mac_mapper, left_ip_addr, left_mac_addr);
  if (ret < 0) {
    log_trace("get_ip_mapper fail");
    return -1;
  } else if (!ret) {
    log_trace("src MAC not found for bridge connection left_ip=%s, right_ip=%s", left_ip_addr, right_ip_addr);
    return -1;
  }

  ret = get_ip_mapper(&context->mac_mapper, right_ip_addr, right_mac_addr);

  if (ret < 0) {
    log_trace("get_ip_mapper fail");
    return -1;
  } else if (!ret) {
    log_trace("dst MAC not found for bridge connection left_ip=%s, right_ip=%s", left_ip_addr, right_ip_addr);
    return -1;
  }

  log_trace("ADD_BRIDGE left_ip=%s, right_ip=%s", left_ip_addr, right_ip_addr);

  if (check_bridge_exist(context->bridge_list, left_mac_addr, right_mac_addr) > 0) {
    log_trace("Bridge between %s and %s already exists", left_ip_addr, right_ip_addr);
    return 0;
  }

  if (add_bridge_mac_cmd(context, left_mac_addr, right_mac_addr) < 0) {
    log_trace("add_bridge_cmd fail");
    return -1;
  }

  return 0;
}

int remove_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  struct mac_conn_info left_info, right_info;

  log_trace("REMOVE_BRIDGE left_mac=" MACSTR ", right_mac="MACSTR, MAC2STR(left_mac_addr), MAC2STR(right_mac_addr));

  if (remove_bridge_mac(context->bridge_list, left_mac_addr, right_mac_addr) >= 0) {
    if (get_mac_mapper(&context->mac_mapper, left_mac_addr, &left_info) == 1 &&
        get_mac_mapper(&context->mac_mapper, right_mac_addr, &right_info) == 1
    ) {
      if (delete_bridge_ip(context, left_info.ip_addr, right_info.ip_addr) < 0) {
        log_trace("delete_bridge_ip fail");
        return -1;
      }
      if (delete_bridge_ip(context, left_info.ip_addr, right_info.ip_sec_addr) < 0) {
        log_trace("delete_bridge_ip fail");
        return -1;
      }
      if (delete_bridge_ip(context, left_info.ip_sec_addr, right_info.ip_addr) < 0) {
        log_trace("delete_bridge_ip fail");
        return -1;
      }
      if (delete_bridge_ip(context, left_info.ip_sec_addr, right_info.ip_sec_addr) < 0) {
        log_trace("delete_bridge_ip fail");
        return -1;
      }
    }
  } else {
    log_trace("remove_bridge_mac fail");
    return -1;
  }

  return 0;
}

int clear_bridges_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  struct mac_conn *mac_list = NULL;
  int mac_list_len = get_mac_list(&context->mac_mapper, &mac_list);

  log_trace("CLEAR_BRIDGES mac=" MACSTR, MAC2STR(mac_addr));

  if (mac_list != NULL) {
    for (int count = 0; count < mac_list_len; count ++) {
      struct mac_conn el = mac_list[count];
      remove_bridge_cmd(context, mac_addr, el.mac_addr);
    }

    os_free(mac_list);
  }

  return 0;
}

uint8_t* register_ticket_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *label,
                        int vlanid)
{
  log_trace("REGISTER_TICKET for mac=" MACSTR ", label=%s and vlanid=%d", MAC2STR(mac_addr), label, vlanid);

  if (context->ticket != NULL) {
    log_trace("Auth ticket is still active");
    return NULL;
  }

  context->ticket = os_zalloc(sizeof(struct auth_ticket));

  if (context->ticket == NULL) {
    log_err("os_malloc");
    return NULL;
  }

  os_memcpy(context->ticket->issuer_mac_addr, mac_addr, ETH_ALEN);
  strcpy(context->ticket->device_label, label);
  context->ticket->vlanid = vlanid;
  context->ticket->passphrase_len = TICKET_PASSPHRASE_SIZE;

  if (os_get_random_number_s(context->ticket->passphrase, context->ticket->passphrase_len) < 0) {
    log_trace("os_get_random_number_s fail");
    os_free(context->ticket);
    return NULL;
  }

  if (eloop_register_timeout(TICKET_TIMEOUT, 0, eloop_ticket_timeout_handler, NULL, (void *)context) < 0) {
    log_trace("eloop_register_timeout fail");
    os_free(context->ticket);
    return NULL;
  }

  return context->ticket->passphrase;
}

int clear_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{  
  struct mac_conn conn;
  struct mac_conn_info info;

  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  log_trace("CLEAR_PSK for mac=" MACSTR, MAC2STR(mac_addr));

  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  os_memset(info.pass, 0, AP_SECRET_LEN);
  info.pass_len = 0;
  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    return -1;
  }

  return 0;
}
