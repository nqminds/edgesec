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
 * @file subnet.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the subnet interface services utilites.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/os.h"
#include "utils/if.h"
#include "utils/iw.h"

#include "subnet/subnet_service.h"

uint8_t get_short_subnet(char *subnet_mask)
{
  in_addr_t addr;
  uint8_t short_mask = 0;
  uint32_t shift = 0x80000000U;

  if ((addr = inet_network(subnet_mask)) == -1) {
		log_trace("Invalid subnet mask address");
		return -1;
	}

  for (int i = 0; i < 31; i++) {
    if (addr & shift) short_mask ++;
    shift >>= 1U;
  }

  return short_mask;

}

bool create_subnet_ifs(UT_array *ifinfo_array, bool ignore_error)
{
  config_ifinfo_t *p = NULL;
  char longip[IP_LEN];

  if (ifinfo_array == NULL) {
    log_trace("ifinfo_array param is NULL");
    return false;
  }

  while(p = (config_ifinfo_t*) utarray_next(ifinfo_array, p)) {
    snprintf(longip, IP_LEN,"%s/%d", p->ip_addr, (int)get_short_subnet(p->subnet_mask));

    log_trace("Creating ifname=%s ip_addr=%s brd_addr=%s subnet_mask=%s", p->ifname, p->ip_addr, p->brd_addr, p->subnet_mask);

    if (!create_interface(p->ifname, "bridge")) {
      log_trace("create_interface fail");
      if (ignore_error) {
        log_trace("ignore error proceed to next interface");
        continue;
      } else
        return false;
    }

    if (!set_interface_ip(longip, p->brd_addr, p->ifname)) {
      log_trace("set_interface fail");
      return false;
    }

    if (!set_interface_state(p->ifname, true)) {
      log_trace("set_interface_state fail");
      return false;
    }
  }

  return true;
}

bool get_nat_if_ip(const char *nat_interface, char **ip_buf)
{
  UT_array *netip_list = NULL;
  unsigned int if_idx = if_nametoindex(nat_interface);

  log_debug("Testing get_interface for %s", nat_interface);

  if (!if_idx) {
    log_err("if_nametoindex");
    goto err;
  }

  netip_list = get_interfaces(if_idx);

  if (netip_list == NULL) {
    log_err("Interfrace %s not found", nat_interface);
    goto err;
  }

  netif_info_t *el = (netif_info_t*) utarray_back(netip_list);
  if (el == NULL) {
    log_err("Interfrace list empty");
    goto err;
  }

  if (el->ifa_family == AF_INET) {
    *ip_buf = allocate_string(el->ip_addr);
  }

  utarray_free(netip_list);
  return true;

err:
  if (netip_list)
    utarray_free(netip_list);
  return false;
}

bool create_if_mapper(UT_array *config_ifinfo_array, hmap_if_conn **hmap)
{
  config_ifinfo_t *p = NULL;
  in_addr_t addr;

  if (config_ifinfo_array != NULL) {
    while(p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) {
      log_trace("Adding ip=%s subnet=%s ifname=%s to mapper", p->ip_addr, p->ifname, p->subnet_mask);
      if(!ip_2_nbo(p->ip_addr, p->subnet_mask, &addr)) {
        log_trace("ip_2_nbo fail");
        free_if_mapper(hmap);
        return false;
      }

      if (!put_if_mapper(hmap, addr, p->ifname)) {
        log_trace("put_if_mapper fail");
        free_if_mapper(hmap);
        return false;
      }
    }
  }
  return true;
}

bool create_vlan_mapper(UT_array *config_ifinfo_array, hmap_vlan_conn **hmap)
{
  config_ifinfo_t *p = NULL;

  if (config_ifinfo_array != NULL) {
    while(p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) {
      log_trace("Adding vlanid=%d and ifname=%s to mapper", p->vlanid, p->ifname);
      if (!put_vlan_mapper(hmap, p->vlanid, p->ifname)) {
        log_trace("put_if_mapper fail");
        free_vlan_mapper(hmap);
        return false;
      }
    }
  }
  return true;
}

bool init_ifbridge_names(UT_array *config_ifinfo_array, char *if_bridge)
{
  config_ifinfo_t *p = NULL;
  if (config_ifinfo_array != NULL && if_bridge != NULL) {
    while(p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) {
      if (snprintf(p->ifname, IFNAMSIZ, "%s%d", if_bridge, p->vlanid) < 0) {
        return false;
      }
    }
  }

  return true;
}
