/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the firewall service commands.
 */

#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../utils/allocs.h"
#include "../utils/hashmap.h"
#include "../utils/log.h"
#include "../utils/os.h"

#ifdef WITH_UCI_SERVICE
#include "../utils/uci_wrt.h"
#define FIREWALL_SERVICE_RELOAD "reload"
#else
#include "../utils/iptables.h"
#endif

#include "firewall_config.h"

#define IP_FORWARD_PATH "/proc/sys/net/ipv4/ip_forward"

void fw_free_context(struct fwctx *context) {
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

#ifdef WITH_UCI_SERVICE
int run_firewall(struct fwctx *context) {
  if (context->exec_firewall) {
    const char *argv[2] = {FIREWALL_SERVICE_RELOAD, NULL};

    if (context->firewall_bin_path != NULL) {
      return run_argv_command(context->firewall_bin_path, argv, NULL, NULL);
    }
  }

  return 0;
}
#else
int run_firewall(struct fwctx *context) {
  (void)context;

  return 0;
}
#endif

struct fwctx *fw_init_context(hmap_if_conn *if_mapper,
                              hmap_vlan_conn *vlan_mapper,
                              hmap_str_keychar *hmap_bin_paths,
                              UT_array *config_ifinfo_array, char *nat_bridge,
                              char *nat_interface, bool exec_firewall,
                              char *path) {
  if (if_mapper == NULL) {
    log_error("if_mapper param is NULL");
    return NULL;
  }

  if (vlan_mapper == NULL) {
    log_error("vlan_mapper param is NULL");
    return NULL;
  }

  if (hmap_bin_paths == NULL) {
    log_error("hmap_bin_paths param is NULL");
    return NULL;
  }

  if (config_ifinfo_array == NULL) {
    log_error("config_ifinfo_array param is NULL");
    return NULL;
  }

  if (nat_bridge == NULL) {
    log_error("nat_bridge param is NULL");
    return NULL;
  }

  if (nat_interface == NULL) {
    log_error("nat_interface param is NULL");
    return NULL;
  }

  if (path == NULL) {
    log_error("path param is NULL");
    return NULL;
  }

  struct fwctx *fw_ctx = os_zalloc(sizeof(struct fwctx));

  if (fw_ctx == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  fw_ctx->if_mapper = if_mapper;
  fw_ctx->vlan_mapper = vlan_mapper;
  fw_ctx->hmap_bin_paths = hmap_bin_paths;
  fw_ctx->config_ifinfo_array = config_ifinfo_array;
  fw_ctx->nat_bridge = nat_bridge;
  fw_ctx->nat_interface = nat_interface;
  fw_ctx->exec_firewall = exec_firewall;
  fw_ctx->firewall_bin_path = path;
#ifdef WITH_UCI_SERVICE
  if (exec_firewall) {
    if ((fw_ctx->ctx = uwrt_init_context(NULL)) == NULL) {
      log_error("uwrt_init_context fail");
      fw_free_context(fw_ctx);
      return NULL;
    }

    if (uwrt_cleanup_firewall(fw_ctx->ctx) < 0) {
      log_error("uwrt_cleanup_firewall fail");
      fw_free_context(fw_ctx);
      return NULL;
    }

    config_ifinfo_t *p = NULL;
    while ((p = (config_ifinfo_t *)utarray_next(config_ifinfo_array, p)) !=
           NULL) {
      if (uwrt_gen_firewall_zone(fw_ctx->ctx, p->brname) < 0) {
        log_error("uwrt_init_context fail");
        fw_free_context(fw_ctx);
        return NULL;
      }
    }

    if (uwrt_commit_section(fw_ctx->ctx, "firewall") < 0) {
      log_error("uwrt_commit_section fail");
      fw_free_context(fw_ctx);
      return NULL;
    }
  }
#else
  const char *iptables_path = hmap_str_keychar_get(hmap_bin_paths, "iptables");
  if (iptables_path == NULL) {
    log_error("Couldn't find iptables binary");
    fw_free_context(fw_ctx);
    return NULL;
  }

  if ((fw_ctx->ctx = iptables_init(iptables_path, config_ifinfo_array,
                                   exec_firewall)) == NULL) {
    log_error("iptables_init fail");
    fw_free_context(fw_ctx);
    return NULL;
  }
#endif

  if (run_firewall(fw_ctx) < 0) {
    log_error("run_firewall fail");
    fw_free_context(fw_ctx);
    return NULL;
  }

  return fw_ctx;
}

int fw_add_nat(struct fwctx *context, char *ip_addr) {
#ifdef WITH_UCI_SERVICE
  char brname[IF_NAMESIZE];

  if (get_brname_from_ip(context->config_ifinfo_array, ip_addr, brname) < 0) {
    log_error("get_brname_from_ip fail");
    return -1;
  }

  log_debug("Adding uci rule for br=%s br=%s", ip_addr, brname);
  if (uwrt_add_firewall_nat(context->ctx, brname, ip_addr,
                            context->nat_bridge) < 0) {
    log_error("uwrt_add_firewall_nat fail");
    return -1;
  }

  if (uwrt_commit_section(context->ctx, "firewall") < 0) {
    log_error("uwrt_commit_section fail");
    return -1;
  }
#else
  char ifname[IF_NAMESIZE];

  if (get_ifname_from_ip(context->config_ifinfo_array, ip_addr, ifname) < 0) {
    log_error("get_ifname_from_ip fail");
    return -1;
  }

  log_debug("Adding iptable rule for ip=%s if=%s", ip_addr, ifname);
  if (iptables_add_nat(context->ctx, ip_addr, ifname, context->nat_interface) <
      0) {
    log_error("iptables_add_nat fail");
    return -1;
  }
#endif

  if (run_firewall(context) < 0) {
    log_error("run_firewall fail");
    return -1;
  }

  return 0;
}

int fw_remove_nat(struct fwctx *context, char *ip_addr) {
#ifdef WITH_UCI_SERVICE
  log_debug("Removing uci rule for ip=%s", ip_addr);
  if (uwrt_delete_firewall_nat(context->ctx, ip_addr) < 0) {
    log_error("uwrt_delete_firewall_nat fail");
    return -1;
  }

  if (uwrt_commit_section(context->ctx, "firewall") < 0) {
    log_error("uwrt_commit_section fail");
    return -1;
  }
#else
  char ifname[IF_NAMESIZE];

  if (get_ifname_from_ip(context->config_ifinfo_array, ip_addr, ifname) < 0) {
    log_error("get_ifname_from_ip fail");
    return -1;
  }

  log_debug("Removing iptable rule for ip=%s if=%s", ip_addr, ifname);
  if (iptables_delete_nat(context->ctx, ip_addr, ifname,
                          context->nat_interface) < 0) {
    log_error("iptables_delete_nat fail");
    return -1;
  }
#endif

  if (run_firewall(context) < 0) {
    log_error("run_firewall fail");
    return -1;
  }

  return 0;
}

int fw_add_bridge(struct fwctx *context, char *ip_addr_left,
                  char *ip_addr_right) {
#ifdef WITH_UCI_SERVICE
  char brname_left[IF_NAMESIZE], brname_right[IF_NAMESIZE];

  if (get_brname_from_ip(context->config_ifinfo_array, ip_addr_left,
                         brname_left) < 0) {
    log_error("get_brname_from_ip fail");
    return -1;
  }

  if (get_brname_from_ip(context->config_ifinfo_array, ip_addr_right,
                         brname_right) < 0) {
    log_error("get_brname_from_ip fail");
    return -1;
  }

  log_debug("Adding uci rule for sip=%s sbr=%s dip=%s dbr=%s", ip_addr_left,
            brname_left, ip_addr_right, brname_right);
  if (uwrt_add_firewall_bridge(context->ctx, ip_addr_left, brname_left,
                               ip_addr_right, brname_right) < 0) {
    log_error("uwrt_add_firewall_bridge fail");
    return -1;
  }

  if (uwrt_commit_section(context->ctx, "firewall") < 0) {
    log_error("uwrt_commit_section fail");
    return -1;
  }
#else
  char ifname_left[IF_NAMESIZE], ifname_right[IF_NAMESIZE];

  if (get_ifname_from_ip(context->config_ifinfo_array, ip_addr_left,
                         ifname_left) < 0) {
    log_error("get_ifname_from_ip fail");
    return -1;
  }

  if (get_ifname_from_ip(context->config_ifinfo_array, ip_addr_right,
                         ifname_right) < 0) {
    log_error("get_ifname_from_ip fail");
    return -1;
  }

  log_debug("Adding iptable rule for sip=%s sif=%s dip=%s dif=%s", ip_addr_left,
            ifname_left, ip_addr_right, ifname_right);
  if (iptables_add_bridge(context->ctx, ip_addr_left, ifname_left,
                          ip_addr_right, ifname_right) < 0) {
    log_error("iptables_add_bridge fail");
    return -1;
  }
#endif

  if (run_firewall(context) < 0) {
    log_error("run_firewall fail");
    return -1;
  }

  return 0;
}

int fw_remove_bridge(struct fwctx *context, char *ip_addr_left,
                     char *ip_addr_right) {
#ifdef WITH_UCI_SERVICE
  log_debug("Removing uci rule for sip=%s dip=%s", ip_addr_left, ip_addr_right);
  if (uwrt_delete_firewall_bridge(context->ctx, ip_addr_left, ip_addr_right) <
      0) {
    log_error("uwrt_delete_firewall_bridge fail");
    return -1;
  }

  if (uwrt_commit_section(context->ctx, "firewall") < 0) {
    log_error("uwrt_commit_section fail");
    return -1;
  }
#else
  char ifname_left[IF_NAMESIZE], ifname_right[IF_NAMESIZE];

  if (get_ifname_from_ip(context->config_ifinfo_array, ip_addr_left,
                         ifname_left) < 0) {
    log_error("get_ifname_from_ip fail");
    return -1;
  }

  if (get_ifname_from_ip(context->config_ifinfo_array, ip_addr_right,
                         ifname_right) < 0) {
    log_error("get_ifname_from_ip fail");
    return -1;
  }

  log_debug("Removing iptable rule for sip=%s sif=%s dip=%s dif=%s",
            ip_addr_left, ifname_left, ip_addr_right, ifname_right);
  if (iptables_delete_bridge(context->ctx, ip_addr_left, ifname_left,
                             ip_addr_right, ifname_right) < 0) {
    log_error("iptables_add_bridge fail");
    return -1;
  }
#endif

  if (run_firewall(context) < 0) {
    log_error("run_firewall fail");
    return -1;
  }

  return 0;
}

int fw_set_ip_forward(void) {
  char buf[2];
  int fd = open(IP_FORWARD_PATH, O_RDWR);
  if (read(fd, buf, 1) < 0) {
    log_errno("read");
    close(fd);
    return -1;
  }

  log_debug("Current IP forward flag %c", buf[0]);

  if (buf[0] == 0x30) {
    log_debug("Setting IP forward flag to 1");
    if (lseek(fd, 0, SEEK_SET) < 0) {
      log_errno("lseek");
      close(fd);
      return -1;
    }

    buf[0] = 0x31;

    if (write(fd, buf, 1) < 0) {
      log_errno("write");
      close(fd);
      return -1;
    }
  }
  close(fd);
  return 0;
}
