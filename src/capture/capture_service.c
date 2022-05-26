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
#include "header_middleware/packet_queue.h"
#include "pcap_middleware/pcap_queue.h"
#include "pcap_service.h"
#include "header_middleware/sqlite_header_writer.h"
#include "pcap_middleware/sqlite_pcap_writer.h"

#include "../utils/domain.h"
#include "../utils/squeue.h"
#include "../utils/log.h"
#include "../utils/eloop.h"
#include "../utils/list.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL,
                                   NULL};

void construct_pcap_file_name(char *file_name) {
  generate_radom_uuid(file_name);
  strcat(file_name, PCAP_EXTENSION);
}

void add_packet_queue(struct capture_context *context, UT_array *tp_array,
                      struct packet_queue *queue) {
  struct tuple_packet *p = NULL;

  while ((p = (struct tuple_packet *)utarray_next(tp_array, p)) != NULL) {
    if (context->db_write) {
      if (push_packet_queue(queue, *p) == NULL) {
        log_trace("push_packet_queue fail");
        // Free the packet if cannot be added to the queue
        free_packet_tuple(p);
      }
    }
  }
}

void pcap_callback(const void *ctx, const void *pcap_ctx, char *ltype,
                   struct pcap_pkthdr *header, uint8_t *packet) {
  struct capture_context *context = (struct capture_context *)ctx;
  struct pcap_context *pc = (struct pcap_context *)pcap_ctx;
  char cap_id[MAX_RANDOM_UUID_LEN];
  UT_array *tp_array = NULL;

  utarray_new(tp_array, &tp_list_icd);

  generate_radom_uuid(cap_id);

  if (extract_packets(ltype, header, packet, pc->ifname, cap_id, tp_array) >
      0) {
    add_packet_queue(context, tp_array, context->pqueue);
  }

  utarray_free(tp_array);

  if (context->file_write) {
    if (push_pcap_queue(context->cqueue, header, packet) == NULL) {
      log_trace("push_pcap_queue fail");
    } else {
      log_trace("Pushed packet size=%d", header->caplen);
    }
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

int save_pcap_file_data(struct pcap_pkthdr *header, uint8_t *packet,
                        struct capture_context *context,
                        struct pcap_context *pc) {
  char *path = NULL;
  char file_name[MAX_PCAP_FILE_NAME_LENGTH];
  uint64_t timestamp = 0;

  os_to_timestamp(header->ts, &timestamp);
  construct_pcap_file_name(file_name);

  if ((path = construct_path(context->pcap_path, file_name)) == NULL) {
    log_trace("construct_path fail");
    return -1;
  }

  if (dump_file_pcap(pc, path, header, packet) < 0) {
    log_trace("dump_file_pcap fail");
    os_free(path);
    return -1;
  }

  os_free(path);

  if (save_sqlite_pcap_entry(context->db, file_name, timestamp, header->caplen,
                             header->len, pc->ifname, context->filter) < 0) {
    log_trace("save_sqlite_pcap_entry fail");
    return -1;
  }

  return 0;
}

void eloop_tout_handler(void *eloop_ctx, void *user_ctx) {
  struct pcap_context *pc = (struct pcap_context *)eloop_ctx;
  struct capture_context *context = (struct capture_context *)user_ctx;
  struct packet_queue *el_packet;
  struct pcap_queue *el_pcap;

  // Process all packets in the queue
  while (is_packet_queue_empty(context->pqueue) < 1) {
    if ((el_packet = pop_packet_queue(context->pqueue)) != NULL) {
      if (context->db_write) {
        save_packet_statement(context->db, &(el_packet->tp));
      }

      free_packet_tuple(&el_packet->tp);
      free_packet_queue_el(el_packet);
    }
  }

  if (context->file_write) {
    while (is_pcap_queue_empty(context->cqueue) < 1) {
      if ((el_pcap = pop_pcap_queue(context->cqueue)) != NULL) {
        if (save_pcap_file_data(&(el_pcap->header), el_pcap->packet, context,
                                pc) < 0) {
          log_trace("save_pcap_file_data fail");
        }
        free_pcap_queue_el(el_pcap);
      }
    }
  }

  if (eloop_register_timeout(context->eloop, 0, context->process_interval,
                             eloop_tout_handler, (void *)eloop_ctx,
                             (void *)user_ctx) == -1) {
    log_debug("eloop_register_timeout fail");
  }
}

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

int run_capture(struct capture_conf *config) {
  int ret = -1;
  struct capture_context context;
  struct pcap_context *pc = NULL;

  os_memset(&context, 0, sizeof(context));

  if (get_pcap_folder_path(config->capture_db_path, context.pcap_path) < 0) {
    log_error("get_pcap_folder_path fail");
    return -1;
  }

  if (create_dir(context.pcap_path, S_IRWXU | S_IRWXG) < 0) {
    log_error("create_dir fail");
    return -1;
  }

  context.filter = config->filter;
  context.process_interval = config->process_interval * 1000;
  context.buffer_timeout = config->buffer_timeout;
  context.promiscuous = config->promiscuous;
  context.immediate = config->immediate;
  context.file_write = config->file_write;
  context.db_write = config->db_write;
  context.sync_store_size = config->sync_store_size;
  context.sync_send_size = config->sync_send_size;

  log_info("Capture db path=%s", config->capture_db_path);
  log_info("Capturing pcap_path=%s", context.pcap_path);
  log_info("Capturing interface(s)=%s", config->capture_interface);
  log_info("Capturing filter=%s", context.filter);
  log_info("Promiscuous mode=%d", context.promiscuous);
  log_info("Immediate mode=%d", context.immediate);
  log_info("Buffer timeout=%d", context.buffer_timeout);
  log_info("Process interval=%d (milliseconds)", context.process_interval);
  log_info("Sync store size=%ld", context.sync_store_size);
  log_info("Sync send size=%ld", context.sync_send_size);
  log_info("File write=%d", context.file_write);
  log_info("DB write=%d", context.db_write);

  ret = sqlite3_open(config->capture_db_path, &context.db);

  if (ret != SQLITE_OK) {
    log_error("Cannot open database: %s", sqlite3_errmsg(context.db));
    sqlite3_close(context.db);
    return -1;
  }

  context.pqueue = init_packet_queue();

  if (context.pqueue == NULL) {
    log_error("init_packet_queue fail");
    sqlite3_close(context.db);
    return -1;
  }

  context.cqueue = init_pcap_queue();

  if (context.cqueue == NULL) {
    log_error("init_pcap_queue fail");
    free_packet_queue(context.pqueue);
    sqlite3_close(context.db);
    return -1;
  }

  if (context.db_write) {
    ret = init_sqlite_header_db(context.db);

    if (ret < 0) {
      log_error("open_sqlite_header_db fail");
      free_packet_queue(context.pqueue);
      free_pcap_queue(context.cqueue);
      sqlite3_close(context.db);
      return -1;
    }
  }

  if (context.file_write) {
    if (init_sqlite_pcap_db(context.db) < 0) {
      log_error("init_sqlite_pcap_db fail");
      free_packet_queue(context.pqueue);
      free_pcap_queue(context.cqueue);
      sqlite3_close(context.db);
      return -1;
    }
  }

  if ((context.eloop = eloop_init()) == NULL) {
    log_error("eloop_init fail");
    goto fail;
  }

  log_info("Registering pcap for ifname=%s", config->capture_interface);
  if (run_pcap(config->capture_interface, context.immediate,
               context.promiscuous, (int)context.buffer_timeout, context.filter,
               true, pcap_callback, (void *)&context, &pc) < 0) {
    log_error("run_pcap fail");
    goto fail;
  }

  if (pc != NULL) {
    if (eloop_register_read_sock(context.eloop, pc->pcap_fd,
                                 eloop_read_fd_handler, (void *)pc,
                                 (void *)NULL) == -1) {
      log_error("eloop_register_read_sock fail");
      goto fail;
    }
  } else {
    log_debug("Empty pcap context");
    goto fail;
  }

  if (eloop_register_timeout(context.eloop, 0, context.process_interval,
                             eloop_tout_handler, (void *)pc,
                             (void *)&context) == -1) {
    log_error("eloop_register_timeout fail");
    goto fail;
  }

  eloop_run(context.eloop);
  log_info("Capture ended.");

  /* And close the session */
  close_pcap(pc);
  free_packet_queue(context.pqueue);
  free_pcap_queue(context.cqueue);
  eloop_free(context.eloop);
  sqlite3_close(context.db);
  return 0;

fail:
  close_pcap(pc);
  free_packet_queue(context.pqueue);
  free_pcap_queue(context.cqueue);
  eloop_free(context.eloop);
  sqlite3_close(context.db);
  return -1;
}

void *capture_thread(void *arg) {
  struct capture_conf *config = (struct capture_conf *)arg;

  if (arg != NULL) {
    if (run_capture(config) < 0) {
      log_error("start_default_analyser fail");
    }
  }

  return NULL;
}
int run_capture_thread(struct capture_conf *config, pthread_t *id) {
  log_info("Running the capture thread");
  if (pthread_create(id, NULL, capture_thread, (void *)config) != 0) {
    log_errno("pthread_create");
    return -1;
  }

  return 0;
}
