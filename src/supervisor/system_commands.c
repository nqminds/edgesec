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
 * @file system_commands.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the system commands.
 */
#include <sys/un.h>
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
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/base64.h"
#include "../utils/eloop.h"
#include "../utils/iptables.h"

#define PING_REPLY  "PONG"

int set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr,
  char *ip_addr, bool add)
{
  UT_array *mac_list_arr;
  uint8_t *p = NULL;
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info right_info, info;
  int ret;

  init_default_mac_info(&info, context->default_open_vlanid, context->allow_all_nat);

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr, ifname)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

  ret = get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  if (ret < 0) {
    log_trace("get_mac_mapper fail");
    return -1;
  }

  os_memcpy(info.ifname, ifname, IFNAMSIZ);
  os_memcpy(conn.mac_addr, mac_addr, ETH_ALEN);
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));
          
  if (add) os_strlcpy(conn.info.ip_addr, ip_addr, IP_LEN);
  else os_memset(conn.info.ip_addr, 0x0, IP_LEN);

  log_trace("SET_IP type=%d mac=" MACSTR " ip=%s if=%s", add, MAC2STR(mac_addr), ip_addr, ifname);
  if (!save_mac_mapper(context, conn)) {
    log_trace("save_mac_mapper fail");
    return -1;
  }

  // Change the NAT iptables rules
  if (add && info.nat) {
    log_trace("Adding NAT rule");
    if (!iptables_add_nat(context->iptables_ctx, ip_addr, ifname, context->nat_interface)) {
      log_trace("iptables_add_nat fail");
      return -1;
    }
  } else if (!add && info.nat){
    log_trace("Deleting NAT rule");
    if (!iptables_delete_nat(context->iptables_ctx, ip_addr, ifname, context->nat_interface)) {
      log_trace("iptables_delete_nat fail");
      return -1;
    }
  }

  // Change the bridge iptables rules
  // Get the list of all dst MACs to update the iptables
  if(get_src_mac_list(context->bridge_list, conn.mac_addr, &mac_list_arr) >= 0) {
    while((p = (uint8_t *) utarray_next(mac_list_arr, p)) != NULL) {
      if(get_mac_mapper(&context->mac_mapper, p, &right_info) == 1) {
        if (validate_ipv4_string(right_info.ip_addr)) {
          if (add) {
            log_trace("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", conn.info.ip_addr, conn.info.ifname, right_info.ip_addr, right_info.ifname);
            if (!iptables_add_bridge(context->iptables_ctx, conn.info.ip_addr, conn.info.ifname, right_info.ip_addr, right_info.ifname)) {
              log_trace("iptables_add_bridge fail");
              utarray_free(mac_list_arr);
              return -1;
            }
          } else {
            log_trace("Removing iptable rule for sip=%s sif=%s dip=%s dif=%s", info.ip_addr, info.ifname, right_info.ip_addr, right_info.ifname);
            if (!iptables_delete_bridge(context->iptables_ctx, info.ip_addr, info.ifname, right_info.ip_addr, right_info.ifname)) {
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

char* ping_cmd(void)
{
  return os_strdup(PING_REPLY);
}

int subscribe_events_cmd(struct supervisor_context *context, struct sockaddr_un *addr, int addr_len)
{
  return -1;
}