/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @brief File containing the definition of the ip generic interface utilities.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "allocs.h"
#include "log.h"
#include "os.h"
#include "net.h"

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

int run_ip(char *path, char *argv[]) {
  return run_argv_command(path, argv, NULL, NULL);
}

int ipgen_new_interface(char *path, char *ifname, char *type) {
  char *argv[7] = {"link", "add", "name", ifname, "type", type, NULL};
  return run_ip(path, argv);
}

int ipgen_set_interface_ip(char *path, char *ifname, char *ip_addr,
                           char *brd_addr) {
  char *argv[8] = {"addr",   "add", ip_addr, "brd",
                   brd_addr, "dev", ifname,  NULL};
  return run_ip(path, argv);
}

int ipgen_set_interface_state(char *path, char *ifname, bool state) {
  char *argv[5] = {"link", "set", ifname, NULL, NULL};
  argv[3] = (state) ? "up" : "down";
  return run_ip(path, argv);
}

int ipgen_create_interface(struct ipgenctx *context, char *ifname, char *type,
                           char *ip_addr, char *brd_addr, char *subnet_mask) {
  (void)context;

  char longip[OS_INET_ADDRSTRLEN];

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

  snprintf(longip, OS_INET_ADDRSTRLEN, "%s/%d", ip_addr,
           (int)get_short_subnet(subnet_mask));

  if (ipgen_new_interface(context->ipcmd_path, ifname, type) < 0) {
    log_trace("ipgen_new_interface fail");
    return -1;
  }

  if (ipgen_set_interface_ip(context->ipcmd_path, ifname, longip, brd_addr) <
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

int ipgen_reset_interface(struct ipgenctx *context, char *ifname) {
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
