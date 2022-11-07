/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the system commands.
 */
#include <sys/un.h>
#include <libgen.h>
#include <utarray.h>

#include "system_commands.h"
#include "mac_mapper.h"
#include "supervisor.h"
#include "supervisor_utils.h"
#include "sqlite_macconn_writer.h"
#include "network_commands.h"
#include "subscriber_events.h"

#include "../ap/ap_config.h"
#include "../ap/ap_service.h"
#include "../capture/capture_service.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/base64.h"
#include "../utils/eloop.h"
#include "../utils/sockctl.h"
#include "../utils/iface_mapper.h"

#define PING_REPLY "PONG\n"

int set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr,
               char *ip_addr, enum DHCP_IP_TYPE ip_type) {
  UT_array *mac_list_arr;
  uint8_t *p = NULL;
  char ifname[IFNAMSIZ];
  struct mac_conn conn;
  struct mac_conn_info right_info, info;
  int ret;
  bool add = (ip_type == DHCP_IP_NEW || ip_type == DHCP_IP_OLD);
  bool primary;

  init_default_mac_info(&info, context->default_open_vlanid,
                        context->allow_all_nat);

  if (get_ifname_from_ip(context->config_ifinfo_array, ip_addr, ifname) < 0) {
    log_error("get_ifname_from_ip fail");
    return -1;
  }

  ret = get_mac_mapper(&context->mac_mapper, mac_addr, &info);
  if (ret < 0) {
    log_error("get_mac_mapper fail");
    return -1;
  }

  switch (ip_type) {
    case DHCP_IP_NEW:
    case DHCP_IP_OLD:
      if (strcmp(info.ip_addr, ip_addr) == 0) {
        log_trace("IP %s already assigned as primary", ip_addr);
        return 0;
      } else if (strcmp(info.ip_sec_addr, ip_addr) == 0) {
        log_trace("IP %s already assigned as secondary", ip_addr);
        return 0;
      }

      if (!strlen(info.ip_addr)) {
        os_strlcpy(info.ip_addr, ip_addr, OS_INET_ADDRSTRLEN);
        primary = true;
      } else if (strlen(info.ip_addr) && !strlen(info.ip_sec_addr)) {
        os_strlcpy(info.ip_sec_addr, ip_addr, OS_INET_ADDRSTRLEN);
        primary = false;
      } else {
        log_error("IPs already present");
        return -1;
      }
      break;
    case DHCP_IP_DEL:
      if (strcmp(info.ip_addr, ip_addr) == 0) {
        os_memset(info.ip_addr, 0x0, OS_INET_ADDRSTRLEN);
      }

      if (strcmp(info.ip_sec_addr, ip_addr) == 0) {
        os_memset(info.ip_sec_addr, 0, OS_INET_ADDRSTRLEN);
      }
      break;
    case DHCP_IP_ARP:
      log_trace("DHCP ARP request");
      return 0;
    default:
      log_error("Wrong DHCP IP type");
      return -1;
  }

  os_memcpy(info.ifname, ifname, IFNAMSIZ);
  os_memcpy(conn.mac_addr, mac_addr, ETHER_ADDR_LEN);
  os_memcpy(&conn.info, &info, sizeof(struct mac_conn_info));

  log_debug("SET_IP type=%d mac=" MACSTR " ip=%s if=%s", ip_type,
            MAC2STR(mac_addr), ip_addr, ifname);
  if (save_mac_mapper(context, conn) < 0) {
    log_error("save_mac_mapper fail");
    return -1;
  }

  if (add) {
    if (send_events_subscriber(context, SUBSCRIBER_EVENT_IP, MACSTR " %s %d %d",
                               MAC2STR(mac_addr), ip_addr, ip_type,
                               primary) < 0) {
      log_error("send_events_subscriber fail");
      return -1;
    }
  }

  // Change the NAT iptables rules
  if (add && info.nat) {
    log_debug("Adding NAT rule");
    if (add_nat_ip(context, ip_addr) < 0) {
      log_error("add_nat_ip fail");
      return -1;
    }
  } else if (!add && info.nat) {
    log_debug("Deleting NAT rule");
    if (remove_nat_ip(context, ip_addr) < 0) {
      log_error("remove_nat_ip fail");
      return -1;
    }
  }

  // Change the bridge iptables rules
  // Get the list of all dst MACs to update the iptables
  if (get_src_mac_list(context->bridge_list, mac_addr, &mac_list_arr) < 0) {
    log_error("get_src_mac_list fail");
    return -1;
  }

  while ((p = (uint8_t *)utarray_next(mac_list_arr, p)) != NULL) {
    if (get_mac_mapper(&context->mac_mapper, p, &right_info) == 1) {
      if (add) {
        if (add_bridge_ip(context, ip_addr, right_info.ip_addr) < 0) {
          log_error("add_bridge_ip fail");
          utarray_free(mac_list_arr);
          return -1;
        }
        if (add_bridge_ip(context, ip_addr, right_info.ip_sec_addr) < 0) {
          log_error("add_bridge_ip fail");
          utarray_free(mac_list_arr);
          return -1;
        }
      } else {
        if (delete_bridge_ip(context, ip_addr, right_info.ip_addr) < 0) {
          log_error("delete_bridge_ip fail");
          utarray_free(mac_list_arr);
          return -1;
        }
        if (delete_bridge_ip(context, ip_addr, right_info.ip_sec_addr) < 0) {
          log_error("delete_bridge_ip fail");
          utarray_free(mac_list_arr);
          return -1;
        }
      }
    }
  }

  utarray_free(mac_list_arr);
  return 0;
}

char *ping_cmd(void) { return os_strdup(PING_REPLY); }

int subscribe_events_cmd(struct supervisor_context *context,
                         struct client_address *addr) {
  log_debug("SUBSCRIBE_EVENTS with size=%d and type=%d", addr->len, addr->type);
  return add_events_subscriber(context, addr);
}
