/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the protobuf middleware
 * utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <sqlite3.h>

#include "protobuf_encoder.h"
#include "protobuf_middleware.h"

#include "../../../utils/allocs.h"
#include "../../../utils/os.h"
#include "../../../utils/log.h"
#include "../../../utils/squeue.h"
#include "../../../utils/eloop.h"

#include "../../pcap_service.h"
#include "../header_middleware/packet_decoder.h"
#include "../header_middleware/packet_queue.h"

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL,
                                   free_packet};


int pipe_protobuf_packets(const char *path, int *fd, UT_array *packets) {
  struct tuple_packet *p = NULL;
  while ((p = (struct tuple_packet *)utarray_next(packets, p)) != NULL) {
    uint8_t *buffer = NULL;
    ssize_t length;
    if ((length = encode_protobuf_wrapper(p, &buffer)) < 0) {
      log_error("encode_protobuf_packet fail");
      return -1;
    }

    if (open_write_nonblock(path, fd, buffer, length) < 0) {
      log_error("open_write_nonblock fail");
      os_free(buffer);
      return -1;
    }

    os_free(buffer);
  }

  return 0;
}

void free_protobuf_middleware(struct middleware_context *context) {
  if (context != NULL) {
    if (context->mdata != NULL) {
      os_free(context->mdata);
    }
    os_free(context);
  }
}

struct middleware_context *init_protobuf_middleware(sqlite3 *db, char *db_path,
                                               struct eloop_data *eloop,
                                               struct pcap_context *pc,
                                               char *params) {
  (void)db_path;

  struct middleware_context *context = NULL;

  log_info("Init protobuf middleware...");

  if ((context = os_zalloc(sizeof(struct middleware_context))) == NULL) {
    log_errno("zalloc");
    return NULL;
  }

  context->db = db;
  context->eloop = eloop;
  context->pc = pc;
  context->params = params;

  int *pipe_fd = NULL;
  if ((pipe_fd = os_zalloc(sizeof(int))) == NULL) {
    log_errno("os_zalloc");
    free_protobuf_middleware(context);
    return NULL;
  }

  context->mdata = (void *) pipe_fd;

  return context;
}

int process_protobuf_middleware(struct middleware_context *context,
                           const char *ltype, struct pcap_pkthdr *header,
                           uint8_t *packet, char *ifname) {
  char cap_id[MAX_RANDOM_UUID_LEN];

  if (context == NULL) {
    log_error("context param is NULL");
    return -1;
  }

  if (context->mdata == NULL) {
    log_error("mdata param is NULL");
    return -1;
  }

  if (context->params == NULL) {
    log_error("params param is NULL");
    return -1;
  }

  char *pipe_path = context->params;
  int *pipe_fd = (int *)context->mdata;

  UT_array *packets = NULL;
  utarray_new(packets, &tp_list_icd);

  generate_radom_uuid(cap_id);
  int npackets = extract_packets(ltype, header, packet, ifname, cap_id, packets);

  if (npackets < 0) {
    log_error("extract_packets fail");
  } else if (npackets > 0) {
    if (pipe_protobuf_packets(pipe_path, pipe_fd, packets) < 0) {
      log_error("pipe_protobuf_packets fail");
    }
  }

  utarray_free(packets);

  return 0;
}

struct capture_middleware protobuf_middleware = {
    .init = init_protobuf_middleware,
    .process = process_protobuf_middleware,
    .free = free_protobuf_middleware,
    .name = "protobuf middleware",
};
