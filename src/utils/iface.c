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
 * @file iface.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the network interface utilities.
 */

#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
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

#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#include "allocs.h"
#include "os.h"
#include "log.h"
#include "iface.h"
#include "ifaceu.h"
#include "net.h"
#include "iface_mapper.h"

#ifdef WITH_NETLINK_SERVICE
#include "nl.h"
#elif WITH_UCI_SERVICE
#include "uci_wrt.h"
#elif WITH_IP_GENERIC_SERVICE
#include "ipgen.h"
#endif

#include "utarray.h"

static const UT_icd netif_info_icd = {sizeof(netif_info_t), NULL, NULL, NULL};

void iface_free_context(struct iface_context *ctx)
{
  if (ctx != NULL) {
#ifdef WITH_UCI_SERVICE
    if (ctx->context != NULL) {
      uwrt_free_context(ctx->context);
    }
#elif WITH_NETLINK_SERVICE
    if (ctx->context != NULL) {
      nl_free_context(ctx->context);
    }
#elif WITH_IP_GENERIC_SERVICE
    if (ctx->context != NULL) {
      ipgen_free_context(ctx->context);
    }
#endif
    os_free(ctx);
  }
}

struct iface_context* iface_init_context(void *params)
{
  struct iface_context *ctx = os_zalloc(sizeof(struct iface_context));

  if (ctx == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

#ifdef WITH_UCI_SERVICE
  (void) params;

  if ((ctx->context = uwrt_init_context(NULL)) == NULL) {
    log_trace("uwrt_init_context fail");
    iface_free_context(ctx);
    return NULL;
  }
#elif WITH_NETLINK_SERVICE
  (void) params;

  if ((ctx->context = nl_init_context()) == NULL) {
    log_trace("nl_init_context fail");
    iface_free_context(ctx);
    return NULL;
  }
#elif WITH_IP_GENERIC_SERVICE
  if ((ctx->context = ipgen_init_context((char*) params)) == NULL) {
    log_trace("ipgen_init_context fail");
    iface_free_context(ctx);
    return NULL;
  }
#endif

  return ctx;
}

UT_array *iface_get(char *ifname)
{
  struct ifaddrs *ifaddr;
  int ret;
  char ipaddr[NI_MAXHOST];
  UT_array *interfaces = NULL;
  netif_info_t nif;

  if (getifaddrs(&ifaddr) == -1) {
    log_err("getifaddrs");
    return NULL;
  }

  utarray_new(interfaces, &netif_info_icd);

  for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }
    os_memset(&nif, 0, sizeof(netif_info_t));

    nif.ifa_family = ifa->ifa_addr->sa_family;
    strcpy(nif.ifname, ifa->ifa_name);

    if (nif.ifa_family == AF_INET || nif.ifa_family == AF_INET6) {
      ret = getnameinfo(ifa->ifa_addr,
        (nif.ifa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
        ipaddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

      if (ret != 0) {
        log_err("getnameinfo");
        utarray_free(interfaces);
        return NULL;
      }

      if (nif.ifa_family == AF_INET) {
        os_strlcpy(nif.ip_addr, ipaddr, IP_LEN);
      } else if (nif.ifa_family == AF_INET6) {
        os_strlcpy(nif.ip_addr6, ipaddr, OS_INET6_ADDRSTRLEN);
      }

      if (ifname == NULL) {
        utarray_push_back(interfaces, &nif);
      } else {
        if (strcmp(ifname, nif.ifname) == 0) {
          utarray_push_back(interfaces, &nif);
          break;
        }
      }
    }
  }

  freeifaddrs(ifaddr);
  return interfaces;
}


char* iface_get_vlan(char *buf)
{
#ifdef WITH_NETLINK_SERVICE
	return nl_get_valid_iw(buf);
#else
  (void) buf;

	log_trace("iface_get_vlan not implemented");
	return NULL;
#endif
}

int reset_interface(struct iface_context *ctx, char *ifname)
{
  log_trace("Reseting interface state for if_name=%s", ifname);
#ifdef WITH_NETLINK_SERVICE
  (void) ctx;
	return nl_reset_interface(ifname);
#elif WITH_IP_GENERIC_SERVICE
  return ipgen_reset_interface(ctx->context, ifname);
#else
  (void) ctx;
  (void) ifname;

	log_trace("reset_interface not implemented");
	return -1;
#endif
}

int iface_create(struct iface_context *ctx, char *brname, char *ifname,
                 char *type, char *ip_addr, char *brd_addr, char *subnet_mask)
{
#ifdef WITH_NETLINK_SERVICE
  (void) brname;
	return nl_create_interface(ctx->context, ifname, type, ip_addr, brd_addr, subnet_mask);
#elif WITH_UCI_SERVICE
  (void) ifname;
  return uwrt_create_interface(ctx->context, brname, type, ip_addr, brd_addr, subnet_mask);
#elif WITH_IP_GENERIC_SERVICE
  return ipgen_create_interface(ctx->context, ifname, type, ip_addr, brd_addr, subnet_mask);
#else
  (void) ctx;
  (void) brname;
  (void) ifname;
  (void) type;
  (void) ip_addr;
  (void) brd_addr;
  (void) subnet_mask;

	log_trace("iface_create not implemented");
	return -1;
#endif
}

int iface_commit(struct iface_context *ctx)
{
  log_trace("Commiting interface changes");
#ifdef WITH_NETLINK_SERVICE
  (void) ctx;
  return 0;
#elif WITH_UCI_SERVICE
  return uwrt_commit_section(ctx->context, "network");
#elif WITH_IP_GENERIC_SERVICE
  (void) ctx;
  return 0;
#else
  (void) ctx;
	log_trace("iface_commit not implemented");
	return -1;
#endif
}