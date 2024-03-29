/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the ip generic interface utilities.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "allocs.h"
#include "log.h"
#include "net.h"
#include "os.h"

#include "ipgen.h"

struct ipgenctx *ipgen_init_context(char *path) {
  if (path == NULL) {
    log_trace("ip param is NULL");
    return NULL;
  }

  struct ipgenctx *context = os_zalloc(sizeof(struct ipgenctx));

  if (context == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  os_strlcpy(context->ipcmd_path, path, MAX_OS_PATH_LEN);

  return context;
}

/**
 * @brief Frees the ipgen context
 *
 * @param context The ipgen context
 */
void ipgen_free_context(struct ipgenctx *context) {
  if (context != NULL) {
    os_free(context);
  }
}

int run_ip(const char *path, const char *const argv[]) {
  return run_argv_command(path, argv, NULL, NULL);
}

int ipgen_new_interface(const char *path, const char *ifname,
                        const char *type) {
  const char *argv[7] = {"link", "add", "name", ifname, "type", type, NULL};
  return run_ip(path, argv);
}

int ipgen_set_interface_ip(const struct ipgenctx *context, const char *ifname,
                           const char *ip_addr, const char *brd_addr,
                           const char *subnet_mask) {
  char longip[OS_INET_ADDRSTRLEN];

  snprintf(longip, OS_INET_ADDRSTRLEN, "%s/%d", ip_addr,
           (int)get_short_subnet(subnet_mask));

  const char *argv[8] = {"addr",   "add", longip, "brd",
                         brd_addr, "dev", ifname, NULL};
  return run_ip(context->ipcmd_path, argv);
}

int ipgen_set_interface_state(const char *path, const char *ifname,
                              bool state) {
  const char *argv[5] = {"link", "set", ifname, (state) ? "up" : "down", NULL};
  return run_ip(path, argv);
}

int ipgen_create_interface(const struct ipgenctx *context, const char *ifname,
                           const char *type, const char *ip_addr,
                           const char *brd_addr, const char *subnet_mask) {
  if (ifname == NULL) {
    log_trace("ifname param is NULL");
    return -1;
  }

  if (type == NULL) {
    log_trace("type param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_trace("ip_addr param is NULL");
    return -1;
  }

  if (brd_addr == NULL) {
    log_trace("brd_addr param is NULL");
    return -1;
  }

  if (subnet_mask == NULL) {
    log_trace("subnet_mask param is NULL");
    return -1;
  }

  if (ipgen_new_interface(context->ipcmd_path, ifname, type) < 0) {
    log_trace("ipgen_new_interface fail");
    return -1;
  }

  if (ipgen_set_interface_ip(context, ifname, ip_addr, brd_addr, subnet_mask) <
      0) {
    log_trace("ipgen_set_interface_ip fail");
    return -1;
  }

  if (ipgen_set_interface_state(context->ipcmd_path, ifname, true) < 0) {
    log_trace("ipgen_set_interface_state fail");
    return -1;
  }

  return 0;
}

int ipgen_reset_interface(const struct ipgenctx *context, const char *ifname) {
  if (ipgen_set_interface_state(context->ipcmd_path, ifname, false) < 0) {
    log_trace("ipgen_set_interface_state fail");
    return -1;
  }

  if (ipgen_set_interface_state(context->ipcmd_path, ifname, true) < 0) {
    log_trace("nl_set_interface_state fail");
    return -1;
  }

  return 0;
}
