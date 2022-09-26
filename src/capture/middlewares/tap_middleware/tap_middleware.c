/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the tap middleware
 * utilities.
 */

/* Create tunatp interface
sudo ip tuntap add mode tap tap0
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <sqlite3.h>

#include "tap_middleware.h"

#include "../../../utils/allocs.h"
#include "../../../utils/os.h"
#include "../../../utils/log.h"
#include "../../../utils/squeue.h"
#include "../../../utils/eloop.h"

#include "../../pcap_service.h"

void free_tap_middleware(struct middleware_context *context) {
  if (context != NULL) {
    struct pcap_context *pctx = (struct pcap_context *)context->mdata;
    if (pctx != NULL) {
      close_pcap(pctx);
    }
    os_free(context);
  }
}

struct middleware_context *init_tap_middleware(sqlite3 *db, char *db_path,
                                               struct eloop_data *eloop,
                                               struct pcap_context *pc,
                                               char *params) {
  (void)db_path;
  (void)eloop;
  struct middleware_context *context = NULL;

  log_info("Init tap middleware...");

  if (db == NULL) {
    log_error("db param is NULL");
    return NULL;
  }

  if (pc == NULL) {
    log_error("pc param is NULL");
    return NULL;
  }

  if (params == NULL) {
    log_error("params param is NULL");
    return NULL;
  }

  if ((context = os_zalloc(sizeof(struct middleware_context))) == NULL) {
    log_errno("zalloc");
    return NULL;
  }

  context->db = db;
  context->eloop = NULL;
  context->pc = pc;
  context->params = params;

  struct pcap_context *pctx = NULL;

  if (run_pcap(params, false, false, 10, NULL, true, NULL, NULL, &pctx) < 0) {
    log_error("run_pcap fail");
    free_tap_middleware(context);
    return NULL;
  }

  context->mdata = (void *)pctx;
  return context;
}

int process_tap_middleware(struct middleware_context *context, const char *ltype,
                           struct pcap_pkthdr *header, uint8_t *packet,
                           char *ifname) {
  (void)ltype;
  (void)ifname;

  if (context == NULL) {
    log_error("context params is NULL");
    return -1;
  }

  struct pcap_context *pctx = (struct pcap_context *)context->mdata;

  int size;
  if ((size = inject_pcap(pctx, packet, header->caplen)) < 0) {
    log_error("inject_pcap");
    return -1;
  } else {
    log_trace("Injected %d bytes", size);
  }
  return 0;
}

struct capture_middleware tap_middleware = {
    .init = init_tap_middleware,
    .process = process_tap_middleware,
    .free = free_tap_middleware,
    .name = "tap middleware",
};
