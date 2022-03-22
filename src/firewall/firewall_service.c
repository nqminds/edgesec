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
 * @file firewall_service.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the firewall service commands.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>


#include "../utils/utarray.h"
#include "../utils/hashmap.h"
#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

#ifdef WITH_UCI_SERVICE
#include "../utils/uci_wrt.h"
#else
#include "../utils/iptables.h"
#endif

#include "firewall_config.h"

#define IP_FORWARD_PATH "/proc/sys/net/ipv4/ip_forward"

void fw_free_context(struct fwctx* context)
{
  if (context != NULL) {
    if (context->ctx != NULL) {
#ifdef WITH_UCI_SERVICE
      uwrt_free_context(context->ctx);
#else
      iptables_free(context->ctx);
#endif
    }
    os_free(context);
  }
}

struct fwctx* fw_init_context(hmap_if_conn *if_mapper,
                              hmap_vlan_conn  *vlan_mapper,
                              hmap_str_keychar *hmap_bin_paths,
                              UT_array *config_ifinfo_array,
                              char *nat_interface,
                              bool exec_firewall)
{
  if (if_mapper == NULL) {
    log_trace("if_mapper param is NULL");
    return NULL;
  }

  if (vlan_mapper == NULL) {
    log_trace("vlan_mapper param is NULL");
    return NULL;
  }

  if (hmap_bin_paths == NULL) {
    log_trace("hmap_bin_paths param is NULL");
    return NULL;
  }

  if (config_ifinfo_array == NULL) {
    log_trace("config_ifinfo_array param is NULL");
    return NULL;
  }

  struct fwctx* fw_ctx = os_zalloc(sizeof(struct fwctx));

  if (fw_ctx == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

  fw_ctx->if_mapper = if_mapper;
  fw_ctx->vlan_mapper = vlan_mapper;
  fw_ctx->hmap_bin_paths = hmap_bin_paths;
  fw_ctx->config_ifinfo_array = config_ifinfo_array;
  fw_ctx->nat_interface = nat_interface;
  fw_ctx->exec_firewall = exec_firewall;

#ifdef WITH_UCI_SERVICE
  if ((fw_ctx->ctx = uwrt_init_context(NULL)) == NULL) {
    log_debug("uwrt_init_context fail");
    fw_free_context(fw_ctx);
    return NULL;
  }
#else
  char *iptables_path = hmap_str_keychar_get(&hmap_bin_paths, "iptables");
  if (iptables_path == NULL) {
    log_debug("Couldn't find iptables binary");
    fw_free_context(fw_ctx);
    return NULL;
  }

  if ((fw_ctx->ctx = iptables_init(iptables_path, config_ifinfo_array, exec_firewall)) == NULL) {
    log_debug("iptables_init fail");
    fw_free_context(fw_ctx);
    return NULL;
  }
#endif

  return fw_ctx;
}

int fw_set_ip_forward(void)
{
  char buf[2];
  int fd = open(IP_FORWARD_PATH, O_RDWR);
  if (read(fd, buf, 1) < 0) {
    log_err("read");
    close(fd);
    return -1;
  }

  log_trace("Current IP forward flag %c", buf[0]);

  if (buf[0] == 0x30) {
    log_trace("Setting IP forward flag to 1");
    if (lseek(fd, 0 , SEEK_SET) < 0) {
      log_err("lseek")  ;
      close(fd);
      return -1;
    }

    buf[0] = 0x31;

	  if (write(fd, buf, 1) < 0) {
      log_err("write");
        close(fd);
        return -1;
    }
  }
  close(fd);
  return 0; 
}

int fw_add_nat(struct fwctx* context, char *ip_addr)
{
  char ifname[IFNAMSIZ];

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr, ifname)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

#ifdef WITH_UCI_SERVICE
  return 0;
#else
  log_trace("Adding iptable rule for ip=%s if=%s", ip_addr, ifname);
  if (!iptables_add_nat(context->ctx, ip_addr, ifname, context->nat_interface)) {
    log_trace("iptables_add_nat fail");
    return -1;
  }
#endif

  return 0;
}

int fw_remove_nat(struct fwctx* context, char *ip_addr)
{
  char ifname[IFNAMSIZ];

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr, ifname)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

#ifdef WITH_UCI_SERVICE
  return 0;
#else
  log_trace("Removing iptable rule for ip=%s if=%s", ip_addr, ifname);
  if (!iptables_delete_nat(context->ctx, ip_addr, ifname, context->nat_interface)) {
    log_trace("iptables_delete_nat fail");
    return -1;
  }
#endif

  return 0;
}

int fw_add_bridge(struct fwctx* context, char *ip_addr_left, char *ip_addr_right)
{
  char ifname_left[IFNAMSIZ], ifname_right[IFNAMSIZ];

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_left, ifname_left)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_right, ifname_right)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

#ifdef WITH_UCI_SERVICE
  return 0;
#else
  log_trace("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", ip_addr_left, ifname_left, ip_addr_right, ifname_right);
  if (!iptables_add_bridge(context->ctx, ip_addr_left, ifname_left, ip_addr_right, ifname_right)) {
    log_trace("iptables_add_bridge fail");
    return -1;
  }
#endif

  return 0;
}

int fw_remove_bridge(struct fwctx* context, char *ip_addr_left, char *ip_addr_right)
{
  char ifname_left[IFNAMSIZ], ifname_right[IFNAMSIZ];

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_left, ifname_left)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

  if (!get_ifname_from_ip(&context->if_mapper, context->config_ifinfo_array, ip_addr_right, ifname_right)) {
    log_trace("get_ifname_from_ip fail");
    return -1;
  }

#ifdef WITH_UCI_SERVICE
  return 0;
#else
  log_trace("Removing iptable rule for sip=%s sif=%s dip=%s dif=%s", ip_addr_left, ifname_left, ip_addr_right, ifname_right);
  if (!iptables_delete_bridge(context->ctx, ip_addr_left, ifname_left, ip_addr_right, ifname_right)) {
    log_trace("iptables_add_bridge fail");
    return -1;
  }
#endif

  return 0;
}