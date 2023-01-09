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
#include "radius_config.h"

int generate_client_conf(struct radius_conf *rconf) {
  FILE *fp = fopen(rconf->client_conf_path, "w");

  if (fp == NULL) {
    log_errno("fopen");
    return -1;
  }

  log_debug("Writing into %s", rconf->client_conf_path);

  fprintf(fp, "%s/%d %s\n", rconf->radius_client_ip, rconf->radius_client_mask, rconf->radius_secret);

  fclose(fp);
  return 0;
}

void close_radius(struct radius_context *ctx) {
  if (ctx != NULL) {
    radius_server_deinit(ctx->srv);
    os_free(ctx);
  }
}

struct radius_context *run_radius(struct eloop_data *eloop,
                                      struct radius_conf *rconf,
                                      mac_conn_fn radius_callback_fn,
                                      void *radius_callback_args) {
  (void)eloop;
  (void)rconf;
  (void)radius_callback_fn;
  (void)radius_callback_args;

  struct radius_context *context = sys_zalloc(sizeof(struct radius_context));

  if (context == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  if (generate_client_conf(rconf) < 0) {
    log_error("generate_client_conf fail");
    close_radius(context);
    return NULL;
  }

  // struct radius_client *client =
  //     init_radius_client(rconf, radius_callback_fn, radius_callback_args);

  // if ((context->srv = radius_server_init(struct radius_server_conf *conf)) == NULL) {
  //   log_error("radius_server_init failure");
  //   close_radius(context);
  //   return NULL;
  // }

  return context;
}
