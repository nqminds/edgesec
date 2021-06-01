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

#include "mac_mapper.h"
#include "supervisor.h"

#include "../utils/os.h"
#include "../utils/log.h"
#include "utils/iptables.h"

void init_default_mac_info(struct mac_conn_info *info, int default_open_vlanid)
{
  info->vlanid = default_open_vlanid;
  info->allow_connection = false;
  info->nat = false;
  info->pass_len = 0;
  os_memset(info->pass, 0, AP_SECRET_LEN);
  os_memset(info->ip_addr, 0, IP_LEN);
  os_memset(info->ifname, 0, IFNAMSIZ);
}

struct mac_conn_info get_mac_conn_cmd(uint8_t mac_addr[], void *mac_conn_arg)
{
  struct supervisor_context *context = (struct supervisor_context *) mac_conn_arg;
  struct mac_conn_info info;

  log_trace("REQUESTED vland id for mac=" MACSTR, MAC2STR(mac_addr));

  if (mac_addr == NULL) {
    log_trace("mac_addr is NULL");
    info.vlanid = -1;
    return info;
  }

  if (context == NULL) {
    log_trace("context is NULL");
    info.vlanid = -1;
    return info;
  }

  int find_mac = get_mac_mapper(&context->mac_mapper, mac_addr, &info);

  if (context->allow_all_connections) {
    log_trace("ALLOWING mac=" MACSTR " on default vlanid=%d", MAC2STR(mac_addr), context->default_open_vlanid);
    info.vlanid = context->default_open_vlanid;
    info.pass_len = context->wpa_passphrase_len;
    memcpy(info.pass, context->wpa_passphrase, info.pass_len);
    return info;
  }
  
  if (find_mac == 1 && info.allow_connection) {
    log_trace("ALLOWING mac=" MACSTR " on vlanid=%d", MAC2STR(mac_addr), info.vlanid);
    return info;
  } else if (find_mac == -1) {
    log_trace("get_mac_mapper fail");
  } else if (find_mac == 0) {
    log_trace("mac=" MACSTR " not found", MAC2STR(mac_addr));
  }

  log_trace("REJECTING mac=" MACSTR, MAC2STR(mac_addr));
  info.vlanid = -1;
  return info;
}

int accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr, int vlanid)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid);

  log_trace("ACCEPT_MAC mac=" MACSTR " with vlanid=%d", MAC2STR(mac_addr), vlanid);

  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.allow_connection = true;
  info.vlanid = vlanid;
  memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (get_vlan_mapper(&context->vlan_mapper, conn.info.vlanid, conn.info.ifname) <= 0) {
    log_trace("get_vlan_mapper fail");
    return -1;
  }

  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_trace("put_mac_mapper fail");
    return -1;
  }

  return 0;
}

int deny_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid);

  log_trace("DENY_MAC mac=" MACSTR, MAC2STR(mac_addr));
  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.allow_connection = false;
  memcpy(&conn.info, &info, sizeof(struct mac_conn_info));
  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_trace("put_mac_mapper fail");
    return -1;
  }

  return 0;
}

int add_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid);

  log_trace("ADD_NAT mac=" MACSTR, MAC2STR(mac_addr));
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.nat = true;
  memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (validate_ipv4_string(info.ip_addr)) {
    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, info.ip_addr, ifname)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }
    if (!add_nat_rules(info.ip_addr, ifname, context->nat_interface)) {
      log_trace("add_nat_rules fail");
      return -1;
    }
  }

  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_trace("put_mac_mapper fail");
    return -1;
  }

  return 0;
}

int remove_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid);

  log_trace("REMOVE_NAT mac=" MACSTR, MAC2STR(mac_addr));
  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  info.nat = false;
  memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (validate_ipv4_string(info.ip_addr)) {
    if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, info.ip_addr, ifname)) {
      log_trace("get_ifname_from_ip fail");
      return -1;
    }
    if (!delete_nat_rules(info.ip_addr, ifname, context->nat_interface)) {
      log_trace("delete_nat_rules fail");
      return -1;
    }
  }

  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_trace("put_mac_mapper fail");
    return -1;
  }

  return 0;
}

int assign_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *pass, int pass_len)
{
  struct mac_conn conn;
  struct mac_conn_info info;
  init_default_mac_info(&info, context->default_open_vlanid);

  log_trace("ASSIGN_PSK mac=" MACSTR ", pass_len=%d", MAC2STR(mac_addr), pass_len);

  get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  memcpy(info.pass, pass, pass_len);
  info.pass_len = pass_len;
  memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_trace("put_mac_mapper fail");
    return -1;
  }

  return 0;
}

int set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *ip_addr, bool add)
{
  UT_array *mac_list_arr;
  uint8_t *p = NULL;
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info right_info, info;
  init_default_mac_info(&info, context->default_open_vlanid);

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr, ifname)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

  if (get_mac_mapper(&context->mac_mapper, mac_addr, &info) < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  memcpy(&conn.info, &info, sizeof(struct mac_conn_info));
          
  if (add) strcpy(conn.info.ip_addr, ip_addr);
  else os_memset(conn.info.ip_addr, 0x0, IP_LEN);

  log_trace("SET_IP type=%d mac=" MACSTR " ip=%s if=%s", add, MAC2STR(mac_addr), ip_addr, ifname);
  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_trace("put_mac_mapper fail");
    return -1;
  }

  // Change the NAT iptables rules
  if (add && info.nat) {
    log_trace("Adding NAT rule");
    if (!add_nat_rules(ip_addr, ifname, context->nat_interface)) {
      log_trace("add_nat_rules fail");
      return -1;
    }
  } else if (!add && info.nat){
    log_trace("Deleting NAT rule");
    if (!delete_nat_rules(ip_addr, ifname, context->nat_interface)) {
      log_trace("delete_nat_rules fail");
      return -1;
    }
  }

  // Change the bridge iptables rules
  // Get the list of all dst MACs to update the iptables
  if(get_src_mac_list(context->bridge_list, conn.mac_addr, &mac_list_arr) >= 0) {
    while(p = (uint8_t *) utarray_next(mac_list_arr, p)) {
      if(get_mac_mapper(&context->mac_mapper, p, &right_info) == 1) {
        if (validate_ipv4_string(right_info.ip_addr)) {
          if (add) {
            log_trace("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", conn.info.ip_addr, conn.info.ifname, right_info.ip_addr, right_info.ifname);
            if (!add_bridge_rules(conn.info.ip_addr, conn.info.ifname, right_info.ip_addr, right_info.ifname)) {
              log_trace("add_bridge_rules fail");
              utarray_free(mac_list_arr);
              return -1;
            }
          } else {
            log_trace("Removing iptable rule for sip=%s sif=%s dip=%s dif=%s", info.ip_addr, info.ifname, right_info.ip_addr, right_info.ifname);
            if (!delete_bridge_rules(info.ip_addr, info.ifname, right_info.ip_addr, right_info.ifname)) {
              log_trace("remove_bridge_rules fail");
              utarray_free(mac_list_arr);
              return -1;
            }
          }
        }
      }
    }
    utarray_free(mac_list_arr);
  } else return -1;

  return 0;
}

int add_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  struct mac_conn_info left_info, right_info;

  if (add_bridge_mac(context->bridge_list, left_mac_addr, right_mac_addr) >= 0) {
    log_trace("ADD_BRIDGE left_mac=" MACSTR " right_mac=" MACSTR, MAC2STR(left_mac_addr), MAC2STR(right_mac_addr));
    if (get_mac_mapper(&context->mac_mapper, left_mac_addr, &left_info) == 1 &&
        get_mac_mapper(&context->mac_mapper, right_mac_addr, &right_info) == 1
    ) {
      if (validate_ipv4_string(left_info.ip_addr) && validate_ipv4_string(right_info.ip_addr)) {
        log_trace("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname);
        if (!add_bridge_rules(left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname)) {
          log_trace("add_bridge_rules fail");
          return -1;
        }
      }
    }
  } else {
    log_trace("add_bridge_mac fail");
    return -1;
  }

  return 0;
}

int remove_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  struct mac_conn_info left_info, right_info;

  if (remove_bridge_mac(context->bridge_list, left_mac_addr, right_mac_addr) >= 0) {
    log_trace("REMOVE_BRIDGE left_mac=" MACSTR " right_mac=" MACSTR, MAC2STR(left_mac_addr), MAC2STR(right_mac_addr));
    if (get_mac_mapper(&context->mac_mapper, left_mac_addr, &left_info) == 1 &&
        get_mac_mapper(&context->mac_mapper, right_mac_addr, &right_info) == 1
    ) {
      if (validate_ipv4_string(left_info.ip_addr) && validate_ipv4_string(right_info.ip_addr)) {
        log_trace("Removing iptable rule for sip=%s sif=%s dip=%s dif=%s", left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname);
        if (!delete_bridge_rules(left_info.ip_addr, left_info.ifname, right_info.ip_addr, right_info.ifname)) {
          log_trace("delete_bridge_rules fail");
          return -1;
        }
      }
    }
  } else {
    log_trace("remove_bridge_mac fail");
    return -1;
  }

  return 0;
}

int set_fingerprint_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *protocol,
                        char *fingerprint)
{
  return 0;
}