/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the interface mapper utilities.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "allocs.h"
#include "iface_mapper.h"
#include "ifaceu.h"
#include "log.h"
#include "net.h"
#include "os.h"

int get_if_mapper(hmap_if_conn *const *hmap, in_addr_t subnet,
                  char ifname[static IF_NAMESIZE]) {
  const hmap_if_conn *s;

  if (hmap == NULL) {
    log_trace("hmap param is NULL");
    return -1;
  }

  if (ifname == NULL) {
    log_trace("ifname param is NULL");
    return -1;
  }

  HASH_FIND(hh, *hmap, &subnet, sizeof(in_addr_t),
            s); /* id already in the hash? */

  if (s != NULL) {
    os_strlcpy(ifname, s->value, IF_NAMESIZE);
    return 1;
  }

  return 0;
}

bool put_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, const char *ifname) {
  hmap_if_conn *s;

  if (hmap == NULL) {
    log_trace("hmap param is NULL");
    return false;
  }

  if (ifname == NULL) {
    log_trace("ifname param is NULL");
    return false;
  }

  HASH_FIND(hh, *hmap, &subnet, sizeof(in_addr_t),
            s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_if_conn *)os_malloc(sizeof(hmap_if_conn));
    if (s == NULL) {
      log_errno("os_malloc");
      return false;
    }

    // Copy the key and value
    s->key = subnet;
    os_strlcpy(s->value, ifname, IF_NAMESIZE);

    HASH_ADD(hh, *hmap, key, sizeof(in_addr_t), s);
  } else {
    // Copy the value
    os_strlcpy(s->value, ifname, IF_NAMESIZE);
  }

  return true;
}

void free_if_mapper(hmap_if_conn **hmap) {
  hmap_if_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current); /* delete it (users advances to next) */
    os_free(current);         /* free it */
  }
}

int get_vlan_mapper(hmap_vlan_conn *const *hmap, int vlanid,
                    struct vlan_conn *conn) {
  if (hmap == NULL) {
    log_trace("hmap param is NULL");
    return -1;
  }

  const hmap_vlan_conn *s;
  HASH_FIND(hh, *hmap, &vlanid, sizeof(int), s); /* id already in the hash? */

  if (s != NULL) {
    if (conn != NULL) {
      *conn = s->value;
    }

    return 1;
  }

  return 0;
}

int copy_vlan_mapper(hmap_vlan_conn *const *hmap, hmap_vlan_conn **copy) {
  const hmap_vlan_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    if (!put_vlan_mapper(copy, &current->value)) {
      log_error("put_vlan_mapper fail");
      return -1;
    }
  }

  return 0;
}

bool put_vlan_mapper(hmap_vlan_conn **hmap, const struct vlan_conn *conn) {
  if (hmap == NULL) {
    log_trace("hmap param is NULL");
    return false;
  }

  if (conn == NULL) {
    log_trace("conn param is NULL");
    return false;
  }

  hmap_vlan_conn *s;
  HASH_FIND(hh, *hmap, &conn->vlanid, sizeof(int),
            s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_vlan_conn *)os_malloc(sizeof(hmap_vlan_conn));

    if (s == NULL) {
      log_errno("os_malloc");
      return false;
    }

    // Initialize with key and value
    *s = (hmap_vlan_conn){
        .key = conn->vlanid,
        .value = *conn,
    };

    HASH_ADD(hh, *hmap, key, sizeof(int), s);
  } else {
    // Copy the value
    s->value = *conn;
  }

  return true;
}

void free_vlan_mapper(hmap_vlan_conn **hmap) {
  hmap_vlan_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current); /* delete it (users advances to next) */
    os_free(current);         /* free it */
  }
}

int find_ifinfo(const UT_array *config_ifinfo_array, const char *ip,
                config_ifinfo_t *ifinfo) {
  for (const config_ifinfo_t *p = utarray_front(config_ifinfo_array); p != NULL;
       p = utarray_next(config_ifinfo_array, p)) {
    in_addr_t addr_subnet;
    if (ip_2_nbo(p->ip_addr, p->subnet_mask, &addr_subnet) < 0) {
      log_trace("ip_2_nbo fail");
      return -1;
    }

    in_addr_t addr_ip;
    if (ip_2_nbo(ip, p->subnet_mask, &addr_ip) < 0) {
      log_trace("ip_2_nbo fail");
      return -1;
    }

    if (addr_ip == addr_subnet) {
      *ifinfo = *p;
      return 0;
    }
  }

  return 1;
}

int get_brname_from_ip(const UT_array *config_ifinfo_array, const char *ip_addr,
                       char brname[static IF_NAMESIZE]) {
  config_ifinfo_t ifinfo;

  if (config_ifinfo_array == NULL) {
    log_trace("config_ifinfo_array param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_trace("ip_addr param is NULL");
    return -1;
  }

  if (brname == NULL) {
    log_trace("brname param is NULL");
    return -1;
  }

  if (find_ifinfo(config_ifinfo_array, ip_addr, &ifinfo) != 0) {
    log_trace("find_ifinfo fail");
    return -1;
  }

  strcpy(brname, ifinfo.brname);

  return 0;
}

int get_ifname_from_ip(const UT_array *config_ifinfo_array, const char *ip_addr,
                       char ifname[static IF_NAMESIZE]) {
  config_ifinfo_t ifinfo;

  if (config_ifinfo_array == NULL) {
    log_trace("config_ifinfo_array param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_trace("ip_addr param is NULL");
    return -1;
  }

  if (ifname == NULL) {
    log_trace("brname param is NULL");
    return -1;
  }

  if (find_ifinfo(config_ifinfo_array, ip_addr, &ifinfo) != 0) {
    log_trace("find_ifinfo fail");
    return -1;
  }

  strcpy(ifname, ifinfo.ifname);

  return 0;
}

bool create_if_mapper(const UT_array *config_ifinfo_array,
                      hmap_if_conn **hmap) {
  if (config_ifinfo_array != NULL) {
    for (const config_ifinfo_t *p = utarray_front(config_ifinfo_array);
         p != NULL; p = utarray_next(config_ifinfo_array, p)) {
      log_trace("Adding ip=%s subnet=%s ifname=%s to mapper", p->ip_addr,
                p->subnet_mask, p->ifname);

      in_addr_t addr;
      if (ip_2_nbo(p->ip_addr, p->subnet_mask, &addr) < 0) {
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

int create_vlan_mapper(const UT_array *config_ifinfo_array,
                       hmap_vlan_conn **hmap) {
  if (config_ifinfo_array != NULL) {
    for (const config_ifinfo_t *p = utarray_front(config_ifinfo_array);
         p != NULL; p = utarray_next(config_ifinfo_array, p)) {
      log_trace("Adding vlanid=%d and ifname=%s to mapper", p->vlanid,
                p->ifname);
      struct vlan_conn vlan_conn = {
          .vlanid = p->vlanid,
          .capture_pid = 0,
      };
      os_memcpy(vlan_conn.ifname, p->ifname, IF_NAMESIZE);
      if (!put_vlan_mapper(hmap, &vlan_conn)) {
        log_trace("put_if_mapper fail");
        free_vlan_mapper(hmap);
        return -1;
      }
    }
  }
  return 0;
}

int init_ifbridge_names(UT_array *config_ifinfo_array, const char *ifname,
                        const char *brname) {
  config_ifinfo_t *p = NULL;

  while ((p = (config_ifinfo_t *)utarray_next(config_ifinfo_array, p)) !=
         NULL) {
    if (snprintf(p->ifname, IF_NAMESIZE, "%s%d", ifname, p->vlanid) < 0) {
      log_errno("snprintf");
      return -1;
    }

    if (snprintf(p->brname, IF_NAMESIZE, "%s%d", brname, p->vlanid) < 0) {
      log_errno("snprintf");
      return -1;
    }
  }

  return 0;
}
