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
 * @file if.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the network interface utilities.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <fnmatch.h>
#include <linux/netlink.h>
#include <arpa/inet.h>

// #include <netlink/genl/genl.h>
// #include <netlink/genl/family.h>
// #include <netlink/genl/ctrl.h>
// #include <netlink/msg.h>
// #include <netlink/attr.h>

#include "linux/if_addr.h"
// #include "linux/if_arp.h"
#include "linux/if_infiniband.h"


#include "nl80211.h"
#include "allocs.h"
#include "os.h"
#include "log.h"
#include "if.h"

#ifdef WITH_NETLINK_LIB
#include "nl.h"
#endif

#include "utarray.h"

bool iface_exists(const char *ifname)
{
	if (ifname == NULL) {
		log_trace("ifname param is NULL");
		return false;
	}

	unsigned int idx = if_nametoindex(ifname);
	if (!idx) {
		return false;
	}

	return true;
}

UT_array *get_interfaces(int if_id)
{
#ifdef WITH_NETLINK_LIB
	return nl_get_interfaces(if_id);
#else
	log_trace("get_interfaces not implemented");
	return NULL;
#endif
}


bool create_interface(char *if_name, char *type)
{
#ifdef WITH_NETLINK_LIB
	return nl_create_interface(if_name, type);
#else
	log_trace("create_interface not implemented");
	return NULL;
#endif
}


bool set_interface_ip(char *ip_addr, char *brd_addr, char *if_name)
{
#ifdef WITH_NETLINK_LIB
	return nl_set_interface_ip(ip_addr, brd_addr, if_name);
#else
	log_trace("set_interface_ip not implemented");
	return NULL;
#endif
}

bool set_interface_state(char *if_name, bool state)
{
#ifdef WITH_NETLINK_LIB
	return nl_set_interface_state(if_name, state);
#else
	log_trace("set_interface_state not implemented");
	return NULL;
#endif
}

bool reset_interface(char *if_name)
{
  log_trace("Resseting interface state for if_name=%s", if_name);
  if (!set_interface_state(if_name, false)) {
    log_trace("set_interface_state fail");
    return false;
  }

  if (!set_interface_state(if_name, true)) {
    log_trace("set_interface_state fail");
    return false;
  }

  return true;
}

int get_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname)
{
  hmap_if_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return -1;
  }

  if(ifname == NULL) {
  	log_trace("ifname param is NULL");
  	return -1;
  }

  HASH_FIND(hh, *hmap, &subnet, sizeof(in_addr_t), s); /* id already in the hash? */

  if (s != NULL) {
	os_memcpy(ifname, s->value, IFNAMSIZ);
    return 1;
  }
 
  return 0;
}

bool put_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname)
{
  hmap_if_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return false;
  }

  if (ifname == NULL) {
	log_trace("ifname param is NULL");
	return false;
  }

  HASH_FIND(hh, *hmap, &subnet, sizeof(in_addr_t), s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_if_conn *) os_malloc(sizeof(hmap_if_conn));
	if (s == NULL) {
	  log_err("os_malloc");
	  return false;
	}

	// Copy the key and value
	s->key = subnet;
    os_memcpy(s->value, ifname, IFNAMSIZ);

    HASH_ADD(hh, *hmap, key, sizeof(in_addr_t), s);
  } else {
	// Copy the value
    os_memcpy(s->value, ifname, IFNAMSIZ);
  }

  return true;	
}

void free_if_mapper(hmap_if_conn **hmap)
{
  hmap_if_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current);  							/* delete it (users advances to next) */
    os_free(current);            						/* free it */
  }
}

int get_vlan_mapper(hmap_vlan_conn **hmap, int vlanid, struct vlan_conn	*conn)
{
  hmap_vlan_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return -1;
  }

  HASH_FIND(hh, *hmap, &vlanid, sizeof(int), s); /* id already in the hash? */

  if (s != NULL) {
	if (conn != NULL) {
	  *conn = s->value;
	}	
    return 1;
  }
 
  return 0;
}

bool put_vlan_mapper(hmap_vlan_conn **hmap, struct vlan_conn *conn)
{
  hmap_vlan_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return false;
  }

  if (conn == NULL) {
	log_trace("conn param is NULL");
	return false;
  }

  HASH_FIND(hh, *hmap, &conn->vlanid, sizeof(int), s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_vlan_conn *) os_malloc(sizeof(hmap_vlan_conn));
	if (s == NULL) {
	  log_err("os_malloc");
	  return false;
	}

	// Copy the key and value
	s->key = conn->vlanid;
    os_memcpy(&s->value, conn, sizeof(struct vlan_conn));

    HASH_ADD(hh, *hmap, key, sizeof(int), s);
  } else {
	// Copy the value
    os_memcpy(&s->value, conn, sizeof(struct vlan_conn));
  }

  return true;	
}

void free_vlan_mapper(hmap_vlan_conn **hmap)
{
  hmap_vlan_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
  	HASH_DEL(*hmap, current);  							/* delete it (users advances to next) */
  	os_free(current);            						/* free it */
  }
}

int ip_2_nbo(char *ip, char *subnet_mask, in_addr_t *addr)
{
  in_addr_t subnet;

  if (addr == NULL) {
	log_trace("addr param is NULL");
	return -1;
  }

  if ((subnet = inet_network(subnet_mask)) == INADDR_NONE) {
	log_trace("Invalid subnet mask address");
	return -1;
  }

  if ((*addr = inet_network(ip)) == INADDR_NONE) {
	log_trace("Invalid ip address");
	return -1;
  }

  *addr = *addr & subnet;

  return 0;
}

const char *inaddr4_2_ip(struct in_addr *addr, char *ip)
{
  return inet_ntop(AF_INET, addr, ip, OS_INET_ADDRSTRLEN);
}

const char *inaddr6_2_ip(struct in6_addr *addr, char *ip)
{
  return inet_ntop(AF_INET6, addr, ip, OS_INET6_ADDRSTRLEN);
}

const char *bit32_2_ip(uint32_t addr, char *ip)
{
  struct in_addr in;
  in.s_addr = addr;
  return inet_ntop(AF_INET, &in, ip, OS_INET_ADDRSTRLEN);
}

int ip4_2_buf(char *ip, uint8_t *buf)
{
  struct in_addr addr;

  if (ip == NULL) {
	log_trace("ip param is NULL");
	return -1;
  }

  if (buf == NULL) {
	log_trace("buf param is NULL");
	return -1;
  }

  if (!validate_ipv4_string(ip)) {
	log_trace("IP wroing format");
	return -1;
  }

  errno = 0;
  if (inet_pton(AF_INET, ip, &addr) < 0) {
	log_err("inet_pton");
	return -1;
  }
  
  buf[0] = (uint8_t) (addr.s_addr & 0x000000FF);
  buf[1] = (uint8_t) ((addr.s_addr >> 8) & 0x000000FF);
  buf[2] = (uint8_t) ((addr.s_addr >> 16) & 0x000000FF);
  buf[3] = (uint8_t) ((addr.s_addr >> 24) & 0x000000FF);

  return 0;
}

int find_subnet_address(UT_array *config_ifinfo_array, char *ip, in_addr_t *subnet_addr)
{
  config_ifinfo_t *p = NULL;
  in_addr_t addr_config;

  if (config_ifinfo_array == NULL) {
    log_trace("config_ifinfo_array param is NULL");
    return false;
  }

  if (ip == NULL) {
	log_trace("ip param is NULL");
	return -1;
  }

  if (subnet_addr == NULL) {
	log_trace("subnet_addr param is NULL");
	return -1;
  }

  while((p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) != NULL) {
	if (ip_2_nbo(p->ip_addr, p->subnet_mask, &addr_config) < 0) {
	  log_trace("ip_2_nbo fail");
	  return -1;
	}

	if (ip_2_nbo(ip, p->subnet_mask, subnet_addr) < 0) {
	  log_trace("ip_2_nbo fail");
	  return -1;
	}

	if (addr_config == *subnet_addr) {
	  return 0;
	}
  }

  return 1;
}

bool get_ifname_from_ip(hmap_if_conn **if_mapper, UT_array *config_ifinfo_array, char *ip, char *ifname)
{
  in_addr_t subnet_addr;

  if (find_subnet_address(config_ifinfo_array, ip, &subnet_addr) != 0) {
    log_trace("find_subnet_address fail");
    return false;
  }

  int ret = get_if_mapper(if_mapper, subnet_addr, ifname);
  if (ret < 0) {
    log_trace("get_if_mapper fail");
    return false;
  } else if (ret == 0) {
		log_trace("subnet not in mapper");
		return false;
  }

  return true;
}

bool validate_ipv4_string(char *ip)
{
  struct sockaddr_in sa;
  char proc_ip[IP_LEN];
  char *netmask_sep = strchr(ip, '/');
  int netmask_char_size, ret;
  size_t ip_len;

  os_memset(proc_ip, 0, IP_LEN);
  if (netmask_sep) {
    ip_len = strlen(ip) - strlen(netmask_sep);
	os_strlcpy(proc_ip, ip, ip_len + 1);

	netmask_char_size = strlen(netmask_sep + 1);
	if (netmask_char_size > 2 || netmask_char_size < 1) {
	  log_trace("Invalid netmask");
	  return false;
	}

	if (!is_number(netmask_sep + 1)) {
	  log_trace("Invalid netmask");
	  return false;
	}

	if (strtol(netmask_sep + 1, (char **)NULL, 10) > 32) {
	  log_trace("Invalid netmask");
	  return false;
	}
  } else os_strlcpy(proc_ip, ip, IP_LEN);

  errno = 0;
  ret = inet_pton(AF_INET, proc_ip, &(sa.sin_addr));
  if (ret == -1) {
	log_err("inet_pton");
	return false;
  }

  return ret > 0;
}