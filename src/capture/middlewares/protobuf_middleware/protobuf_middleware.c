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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <eloop.h>
#include <libgen.h>
#include <sqlite3.h>
#include <string.h>

#include "protobuf_encoder.h"
#include "protobuf_middleware.h"

#include "../../../utils/allocs.h"
#include "../../../utils/log.h"
#include "../../../utils/os.h"
#include "../../../utils/squeue.h"

#include "../../pcap_service.h"
#include "../header_middleware/packet_decoder.h"
#include "../header_middleware/packet_queue.h"

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL,
                                   free_packet};

int pipe_protobuf_tuple_packet(const char *path, int *fd,
                               struct tuple_packet *p) {
  uint8_t *buffer = NULL;
  ssize_t length = encode_protobuf_sync_wrapper(p, &buffer);
  if (length < 0) {
    log_error("encode_protobuf_packet fail");
    return -1;
  }

  if (open_write_nonblock(path, fd, buffer, length) < 0) {
    log_error("open_write_nonblock fail");
    os_free(buffer);
    return -1;
  }

  os_free(buffer);
  return 0;
}

int pipe_protobuf_packets(const char *path, int *fd, UT_array *packets) {
  struct tuple_packet *p = NULL;
  while ((p = (struct tuple_packet *)utarray_next(packets, p)) != NULL) {
    if (pipe_protobuf_tuple_packet(path, fd, p) < 0) {
      log_error("pipe_protobuf_tuple_packet fail");
      return -1;
    }
  }

  return 0;
}

void free_protobuf_middleware(struct middleware_context *context) {
  if (context != NULL) {
    if (context->mdata != NULL) {
      int *fd = (int *)context->mdata;
      close(*fd);
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

  log_info("Init protobuf middleware...");

  struct middleware_context *context =
      sys_zalloc(sizeof(struct middleware_context));
  if (context == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  context->db = db;
  context->eloop = eloop;
  context->pc = pc;
  context->params = params;

  int *pipe_fd = sys_zalloc(sizeof(int));
  if (pipe_fd == NULL) {
    log_errno("sys_zalloc");
    free_protobuf_middleware(context);
    return NULL;
  }

  context->mdata = (void *)pipe_fd;

  return context;
}

int process_protobuf_middleware(struct middleware_context *context,
                                const char *ltype, struct pcap_pkthdr *header,
                                uint8_t *packet, char *ifname) {
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

  int npackets = extract_packets(ltype, header, packet, ifname, packets);

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
