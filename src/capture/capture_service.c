/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file capture_service.c
 * @author Alexandru Mereacre
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
#include <linux/if.h>
#include <libgen.h>
#include <pcap.h>
#include <pthread.h>

#include "capture_config.h"
#include "capture_service.h"
#include "header_middleware/packet_decoder.h"
#include "pcap_middleware/pcap_queue.h"
#include "pcap_service.h"
#include "header_middleware/header_middleware.h"
#include "pcap_middleware/pcap_middleware.h"

#include "../utils/domain.h"
#include "../utils/squeue.h"
#include "../utils/log.h"
#include "../utils/eloop.h"
#include "../utils/list.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

struct capture_thread_context {
  struct capture_conf config;
  char ifname[IFNAMSIZ];
};

struct capture_middleware_context {
  struct middleware_context *hctx;
  struct middleware_context *pctx;
  char interface[IFNAMSIZ];
};

void pcap_callback(const void *ctx, const void *pcap_ctx, char *ltype,
                   struct pcap_pkthdr *header, uint8_t *packet) {

  (void)pcap_ctx;

  struct capture_middleware_context *context =
      (struct capture_middleware_context *)ctx;

  if (process_header_middleware(context->hctx, ltype, header, packet,
                                context->interface) < 0) {
    log_error("process_header_middleware fail");
  }

  if (process_pcap_middleware(context->pctx, ltype, header, packet,
                              context->interface) < 0) {
    log_error("process_pcap_middleware fail");
  }
}

void eloop_read_fd_handler(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)sock;
  (void)sock_ctx;

  struct pcap_context *pc = (struct pcap_context *)eloop_ctx;

  if (capture_pcap_packet(pc) < 0) {
    log_trace("capture_pcap_packet fail");
  }
}

int run_capture(char *ifname, struct capture_conf *config) {
  int ret = -1;
  struct capture_middleware_context context;
  struct pcap_context *pc = NULL;
  struct eloop_data *eloop = NULL;
  sqlite3 *db;

  os_memset(&context, 0, sizeof(context));

  os_strlcpy(context.interface, ifname, IFNAMSIZ);

  log_info("Capture db path=%s", config->capture_db_path);
  log_info("Capturing interface(s)=%s", context.interface);
  log_info("Capturing filter=%s", config->filter);
  log_info("Promiscuous mode=%d", config->promiscuous);
  log_info("Immediate mode=%d", config->immediate);
  log_info("Buffer timeout=%d", config->buffer_timeout);

  ret = sqlite3_open(config->capture_db_path, &db);

  if (ret != SQLITE_OK) {
    log_error("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  if ((eloop = eloop_init()) == NULL) {
    log_error("eloop_init fail");
    goto fail;
  }

  log_info("Registering pcap for ifname=%s", context.interface);
  if (run_pcap(context.interface, config->immediate, config->promiscuous,
               (int)config->buffer_timeout, config->filter, true, pcap_callback,
               (void *)&context, &pc) < 0) {
    log_error("run_pcap fail");
    goto fail;
  }

  if (pc != NULL) {
    if (eloop_register_read_sock(eloop, pc->pcap_fd, eloop_read_fd_handler,
                                 (void *)pc, (void *)NULL) == -1) {
      log_error("eloop_register_read_sock fail");
      goto fail;
    }
  } else {
    log_debug("Empty pcap context");
    goto fail;
  }

  if ((context.hctx = init_header_middleware(db, config->capture_db_path, eloop,
                                             pc)) == NULL) {
    log_error("init_header_middleware fail");
    goto fail;
  }

  if ((context.pctx = init_pcap_middleware(db, config->capture_db_path, eloop,
                                           pc)) == NULL) {
    log_error("init_header_middleware fail");
    goto fail;
  }

  eloop_run(eloop);
  log_info("Capture ended.");

  /* And close the session */
  free_header_middleware(context.hctx);
  free_pcap_middleware(context.pctx);
  close_pcap(pc);
  eloop_free(eloop);
  sqlite3_close(db);
  return 0;

fail:
  free_header_middleware(context.hctx);
  free_pcap_middleware(context.pctx);
  close_pcap(pc);
  eloop_free(eloop);
  sqlite3_close(db);
  return -1;
}

void *capture_thread(void *arg) {
  struct capture_thread_context *context = (struct capture_thread_context *)arg;

  if (arg != NULL) {
    if (run_capture(context->ifname, &context->config) < 0) {
      log_error("start_default_analyser fail");
    }
  }

  os_free(context);

  return NULL;
}
int run_capture_thread(char *ifname, struct capture_conf *config,
                       pthread_t *id) {
  struct capture_thread_context *context = NULL;

  if ((context = os_zalloc(sizeof(struct capture_thread_context))) == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  os_strlcpy(context->ifname, ifname, IFNAMSIZ);
  os_memcpy(&context->config, config, sizeof(struct capture_conf));

  log_info("Running the capture thread");
  if (pthread_create(id, NULL, capture_thread, (void *)context) != 0) {
    log_errno("pthread_create");
    return -1;
  }

  return 0;
}
