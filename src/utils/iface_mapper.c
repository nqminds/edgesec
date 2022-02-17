/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file iface_mapper.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the interface mapper utilities.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <fnmatch.h>
#include <arpa/inet.h>

#include "allocs.h"
#include "os.h"
#include "log.h"
#include "iface_mapper.h"
#include "ifaceu.h"
#include "net.h"
#include "utarray.h"

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

bool create_if_mapper(UT_array *config_ifinfo_array, hmap_if_conn **hmap)
{
  config_ifinfo_t *p = NULL;
  in_addr_t addr;

  if (config_ifinfo_array != NULL) {
    while((p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) != NULL) {
      log_trace("Adding ip=%s subnet=%s ifname=%s to mapper", p->ip_addr, p->ifname, p->subnet_mask);
      if(ip_2_nbo(p->ip_addr, p->subnet_mask, &addr) < 0) {
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
  struct vlan_conn vlan_conn;
  if (config_ifinfo_array != NULL) {
    while((p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) != NULL) {
      log_trace("Adding vlanid=%d and ifname=%s to mapper", p->vlanid, p->ifname);
      vlan_conn.vlanid = p->vlanid;
      os_memcpy(vlan_conn.ifname, p->ifname, IFNAMSIZ);
      vlan_conn.analyser_pid = 0;
      if (!put_vlan_mapper(hmap, &vlan_conn)) {
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
    while((p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) != NULL) {
      if (snprintf(p->ifname, IFNAMSIZ, "%s%d", if_bridge, p->vlanid) < 0) {
        return false;
      }
    }
  }

  return true;
}
