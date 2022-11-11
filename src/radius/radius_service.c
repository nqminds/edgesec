/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the radius service.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>

#include <eloop.h>
#include "radius_server.h"

struct radius_server_data *run_radius(struct eloop_data *eloop,
                                      struct radius_conf *rconf,
                                      void *radius_callback_fn,
                                      void *radius_callback_args) {
  struct radius_client *client =
      init_radius_client(rconf, radius_callback_fn, radius_callback_args);

  return radius_server_init(eloop, rconf->radius_port, client);
}

void close_radius(struct radius_server_data *srv) {
  if (srv != NULL) {
    radius_server_deinit(srv);
  }
}
