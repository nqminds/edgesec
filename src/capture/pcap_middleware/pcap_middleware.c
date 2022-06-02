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
 * @file pcap_middleware.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the pcap middleware
 * utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <sqlite3.h>

#include "pcap_middleware.h"
#include "pcap_queue.h"
#include "sqlite_pcap.h"

#include "../../utils/allocs.h"
#include "../../utils/os.h"
#include "../../utils/log.h"
#include "../../utils/eloop.h"

#include "../pcap_service.h"

#define PCAP_SUBFOLDER_NAME                                                    \
  "./pcap" /* Subfodler name to store raw pcap data                            \
            */

#define PCAP_PROCESS_INTERVAL 10 * 1000 // In microseconds

#define MAX_PCAP_FILE_NAME_LENGTH MAX_RANDOM_UUID_LEN + STRLEN(PCAP_EXTENSION)

struct pcap_middleware_context {
  char pcap_path[MAX_OS_PATH_LEN];
  struct pcap_queue *queue;
};

int get_pcap_folder_path(char *capture_db_path, char *pcap_path) {
  char *db_path = NULL;
  char *parent_path = NULL;
  char *full_path = NULL;

  if (pcap_path == NULL) {
    log_error("pcap_path param is empty");
    return -1;
  }

  if (!os_strnlen_s(capture_db_path, MAX_OS_PATH_LEN)) {
    log_error("capture_db_path is empty");
    return -1;
  }

  if ((db_path = os_strdup(capture_db_path)) == NULL) {
    log_error("os_strdup");
    return -1;
  }

  parent_path = dirname(db_path);

  if ((full_path = construct_path(parent_path, PCAP_SUBFOLDER_NAME)) == NULL) {
    log_trace("construct_path fail");
    os_free(db_path);
    return -1;
  }

  strcpy(pcap_path, full_path);
  os_free(db_path);
  os_free(full_path);

  return 0;
}

void construct_pcap_file_name(char *file_name) {
  generate_radom_uuid(file_name);
  strcat(file_name, PCAP_EXTENSION);
}

int save_pcap_file_data(struct middleware_context *context,
                        struct pcap_pkthdr *header, uint8_t *packet) {
  char *path = NULL;
  char file_name[MAX_PCAP_FILE_NAME_LENGTH];
  uint64_t timestamp = 0;

  struct pcap_middleware_context *pcap_context =
      (struct pcap_middleware_context *)context->mdata;

  os_to_timestamp(header->ts, &timestamp);
  construct_pcap_file_name(file_name);

  if ((path = construct_path(pcap_context->pcap_path, file_name)) == NULL) {
    log_error("construct_path fail");
    return -1;
  }

  if (dump_file_pcap(context->pc, path, header, packet) < 0) {
    log_error("dump_file_pcap fail");
    os_free(path);
    return -1;
  }

  os_free(path);

  if (save_sqlite_pcap_entry(context->db, file_name, timestamp, header->caplen,
                             header->len) < 0) {
    log_error("save_sqlite_pcap_entry fail");
    return -1;
  }

  return 0;
}

void eloop_tout_pcap_handler(void *eloop_ctx, void *user_ctx) {
  (void)eloop_ctx;

  struct middleware_context *context = (struct middleware_context *)user_ctx;
  struct pcap_middleware_context *pcap_context =
      (struct pcap_middleware_context *)context->mdata;
  struct pcap_queue *el;

  while (is_pcap_queue_empty(pcap_context->queue) < 1) {
    if ((el = pop_pcap_queue(pcap_context->queue)) != NULL) {
      if (save_pcap_file_data(context, &(el->header), el->packet) < 0) {
        log_error("save_pcap_file_data fail");
      }
      free_pcap_queue_el(el);
    }
  }

  if (eloop_register_timeout(context->eloop, 0, PCAP_PROCESS_INTERVAL,
                             eloop_tout_pcap_handler, NULL,
                             (void *)user_ctx) == -1) {
    log_error("eloop_register_timeout fail");
  }
}

void free_pcap_middleware(struct middleware_context *context) {
  struct pcap_middleware_context *pcap_context;

  if (context != NULL) {
    if (context->mdata != NULL) {
      pcap_context = (struct pcap_middleware_context *)context->mdata;
      free_pcap_queue(pcap_context->queue);
      os_free(pcap_context);
      context->mdata = NULL;
    }
    os_free(context);
  }
}

struct middleware_context *init_pcap_middleware(sqlite3 *db, char *db_path,
                                                struct eloop_data *eloop,
                                                struct pcap_context *pc) {
  struct middleware_context *context = NULL;
  struct pcap_middleware_context *pcap_context = NULL;

  if (db == NULL) {
    log_error("db param is NULL");
    return NULL;
  }

  if (db_path == NULL) {
    log_error("db_path param is NULL");
    return NULL;
  }

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return NULL;
  }

  if ((context = os_zalloc(sizeof(struct middleware_context))) == NULL) {
    log_errno("zalloc");
    return NULL;
  }

  if ((pcap_context = os_zalloc(sizeof(struct pcap_middleware_context))) ==
      NULL) {
    log_errno("zalloc");
    free_pcap_middleware(context);
    return NULL;
  }

  context->db = db;
  context->eloop = eloop;
  context->pc = pc;
  context->mdata = (void *)pcap_context;

  if (get_pcap_folder_path(db_path, pcap_context->pcap_path) < 0) {
    log_error("get_pcap_folder_path fail");
    free_pcap_middleware(context);
    return NULL;
  }

  if (create_dir(pcap_context->pcap_path, S_IRWXU | S_IRWXG) < 0) {
    log_error("create_dir fail");
    free_pcap_middleware(context);
    return NULL;
  }

  if ((pcap_context->queue = init_pcap_queue()) == NULL) {
    log_error("init_pcap_queue fail");
    free_pcap_middleware(context);
    return NULL;
  }

  if (init_sqlite_pcap_db(db) < 0) {
    log_error("init_sqlite_pcap_db fail");
    free_pcap_middleware(context);
    return NULL;
  }

  if (eloop_register_timeout(eloop, 0, PCAP_PROCESS_INTERVAL,
                             eloop_tout_pcap_handler, NULL,
                             (void *)context) == -1) {
    log_error("eloop_register_timeout fail");
    free_pcap_middleware(context);
    return NULL;
  }

  return context;
}

int process_pcap_middleware(struct middleware_context *context, char *ltype,
                            struct pcap_pkthdr *header, uint8_t *packet,
                            char *ifname) {
  (void)ltype;
  (void)ifname;

  struct pcap_middleware_context *pcap_context;

  if (context == NULL) {
    log_error("context params is NULL");
    return -1;
  }

  if (context->mdata == NULL) {
    log_error("mdata params is NULL");
    return -1;
  }

  pcap_context = (struct pcap_middleware_context *)context->mdata;

  if (push_pcap_queue(pcap_context->queue, header, packet) == NULL) {
    log_error("push_pcap_queue fail");
    return -1;
  } else {
    log_trace("Pushed packet size=%d", header->caplen);
  }

  return 0;
}
