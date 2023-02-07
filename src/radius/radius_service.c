/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the radius service.
 */

#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <eloop.h>
#include "radius_server.h"

struct radius_context *run_radius(struct eloop_data *eloop,
                                  struct radius_conf *rconf,
                                  mac_conn_fn radius_callback_fn,
                                  void *radius_callback_args) {
  (void)eloop;
  (void)rconf;
  (void)radius_callback_fn;
  (void)radius_callback_args;
  // struct radius_client *client =
  //     init_radius_client(rconf, radius_callback_fn, radius_callback_args);

  return NULL;
  // return radius_server_init(eloop, rconf->radius_port, client);
}

void close_radius(struct radius_context *ctx) {
  if (ctx != NULL) {
    radius_server_deinit(ctx->radius_srv);
    os_free(ctx);
  }
}
