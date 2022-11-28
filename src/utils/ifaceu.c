/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the network interface utilities.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>

#include "log.h"

unsigned int iface_nametoindex(const char *ifname) {
  return if_nametoindex(ifname);
}

bool iface_exists(const char *ifname) {
  if (ifname == NULL) {
    log_trace("ifname param is NULL");
    return false;
  }

  if (!iface_nametoindex(ifname)) {
    return false;
  }

  return true;
}
