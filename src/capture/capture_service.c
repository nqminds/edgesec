/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
/**
 * @file capture_service.c
 * @brief File containing the implementation of the capture service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>

#include "capture_config.h"
#include "capture_service.h"
#include "pcap_service.h"

#include "../utils/sockctl.h"
#include "../utils/squeue.h"
#include "../utils/log.h"
#include "../utils/eloop.h"
#include "../utils/list.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

#include "middlewares_list.h"

void pcap_callback(const void *ctx, const void *pcap_ctx, char *ltype,
                   struct pcap_pkthdr *header, uint8_t *packet) {

  (void)pcap_ctx;

  struct capture_middleware_context *context =
      (struct capture_middleware_context *)ctx;

  process_middlewares(context->handlers, ltype, header, packet,
                      context->ifname);
}

void eloop_read_fd_handler(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)sock;
  (void)sock_ctx;

  struct pcap_context *pc = (struct pcap_context *)eloop_ctx;

  if (capture_pcap_packet(pc) < 0) {
    log_trace("capture_pcap_packet fail");
  }
}

int run_capture(struct capture_middleware_context *context) {
  int ret = -1;
  struct pcap_context *pc = NULL;
  struct eloop_data *eloop = NULL;
  sqlite3 *db;

  log_info("Capture db path=%s", context->config.capture_db_path);
  log_info("Capturing interface(s)=%s", context->ifname);
  log_info("Capturing filter=%s", context->config.filter);
  log_info("Promiscuous mode=%d", context->config.promiscuous);
  log_info("Immediate mode=%d", context->config.immediate);
  log_info("Buffer timeout=%d", context->config.buffer_timeout);

  ret = sqlite3_open(context->config.capture_db_path, &db);

  sqlite3_busy_timeout(db, DB_BUSY_TIMEOUT);

  if (ret != SQLITE_OK) {
    log_error("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  if ((eloop = eloop_init()) == NULL) {
    log_error("eloop_init fail");
    goto capture_fail;
  }

  log_info("Registering pcap for ifname=%s", context->ifname);
  if (run_pcap(context->ifname, context->config.immediate,
               context->config.promiscuous, (int)context->config.buffer_timeout,
               context->config.filter, true, pcap_callback, (void *)context,
               &pc) < 0) {
    log_error("run_pcap fail");
    goto capture_fail;
  }

  if (pc != NULL) {
    if (eloop_register_read_sock(eloop, pc->pcap_fd, eloop_read_fd_handler,
                                 (void *)pc, (void *)NULL) == -1) {
      log_error("eloop_register_read_sock fail");
      goto capture_fail;
    }
  } else {
    log_debug("Empty pcap context");
    goto capture_fail;
  }

  context->handlers = assign_middlewares();

  if (init_middlewares(context->handlers, db, context->config.capture_db_path,
                       eloop, pc) < 0) {
    log_error("init_middlewares fail");
    goto capture_fail;
  }

  eloop_run(eloop);
  log_info("Capture ended.");

  /* And close the session */
  close_pcap(pc);
  eloop_free(eloop);
  sqlite3_close(db);
  return 0;

capture_fail:
  close_pcap(pc);
  eloop_free(eloop);
  sqlite3_close(db);
  return -1;
}

void free_capture_context(struct capture_middleware_context *context) {
  if (context != NULL) {
    free_middlewares(context->handlers);
    os_free(context);
  }
}

void *capture_thread(void *arg) {
  struct capture_middleware_context *context =
      (struct capture_middleware_context *)arg;

  if (run_capture(context) < 0) {
    log_error("run_capture fail");
  }

  free_capture_context(context);

  return NULL;
}

int run_capture_thread(char *ifname, struct capture_conf const *config,
                       pthread_t *id) {
  struct capture_middleware_context *context = NULL;

  if ((context = os_zalloc(sizeof(struct capture_middleware_context))) ==
      NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  os_strlcpy(context->ifname, ifname, IF_NAMESIZE);
  os_memcpy(&context->config, config, sizeof(struct capture_conf));

  log_info("Running the capture thread");
  if (pthread_create(id, NULL, capture_thread, (void *)context) != 0) {
    log_errno("pthread_create");
    free_capture_context(context);
    return -1;
  }

  return 0;
}
