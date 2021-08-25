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
 * @file default_analyser.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the default analyser service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <pcap.h>

#include "default_analyser.h"
#include "capture_config.h"
#include "packet_decoder.h"
#include "packet_queue.h"
#include "pcap_queue.h"
#include "pcap_service.h"
#include "sqlite_header_writer.h"
#include "sqlite_pcap_writer.h"

#include "../utils/if.h"
#include "../utils/log.h"
#include "../utils/eloop.h"
#include "../utils/list.h"
#include "../utils/os.h"

#define MAX_PCAP_FILE_NAME_LENGTH     MAX_RANDOM_UUID_LEN + STRLEN(PCAP_EXTENSION)
#define PCAP_DB_NAME                  "pcap-meta" SQLITE_EXTENSION

#ifdef WITH_SQLSYNC_SERVICE
uint32_t run_register_db(char *address, char *name);
uint32_t run_sync_db_statement(char *address, char *name, bool default_db, char *statement);
#endif

void construct_header_db_name(char *name, char *db_name)
{
  strcat(db_name, name);
  strcat(db_name, SQLITE_EXTENSION);
}

void construct_pcap_file_name(char *file_name)
{
  generate_radom_uuid(file_name);
  strcat(file_name, PCAP_EXTENSION);
}

void add_packet_queue(UT_array *tp_array, int count, struct packet_queue *queue)
{
  struct tuple_packet *p = NULL;
  while((p = (struct tuple_packet *) utarray_next(tp_array, p)) != NULL) {
    if (push_packet_queue(queue, *p) == NULL) {
      log_trace("push_packet_queue fail");
      // Free the packet if cannot be added to the queue
      free_packet_tuple(p);
    }
  }
}

void pcap_callback(const void *ctx, struct pcap_pkthdr *header, uint8_t *packet)
{
  struct capture_context *context = (struct capture_context *)ctx;
  UT_array *tp_array = NULL;
  int count;

  if ((count = extract_packets(header, packet,
                               context->interface,
                               context->hostname,
                               context->cap_id, &tp_array)) > 0) {
    add_packet_queue(tp_array, count, context->pqueue);
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

void eloop_read_fd_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  struct capture_context *context = (struct capture_context *) sock_ctx;
  if (capture_pcap_packet(context->pc) < 0) {
    log_trace("capture_pcap_packet fail");
  }
}

int save_pcap_file_data(struct pcap_pkthdr *header, uint8_t *packet, struct capture_context *context)
{
  char *path = NULL;
  char file_name[MAX_PCAP_FILE_NAME_LENGTH];

  construct_pcap_file_name(file_name);

  path = construct_path(context->db_path, file_name);
  if (dump_file_pcap(context->pc, path, header, packet) < 0) {
    log_trace("dump_file_pcap fail");
    os_free(path);
    return -1;
  }

  os_free(path);

  if (save_sqlite_pcap_entry(context->pcap_db, context->cap_id, file_name,
        os_to_timestamp(header->ts),
        header->caplen, header->len, context->interface, context->filter) < 0) {
    log_trace("save_sqlite_pcap_entry fail");
    return -1;
  }

  return 0;
}

void eloop_tout_handler(void *eloop_ctx, void *user_ctx)
{
  struct capture_context *context = (struct capture_context *) user_ctx;
  struct packet_queue *el_packet;
  struct pcap_queue *el_pcap;
  char *traces = NULL;

  // Process all packets in the queue
  while(get_packet_queue_length(context->pqueue)) {
    if ((el_packet = pop_packet_queue(context->pqueue)) != NULL) {
      if (context->db_write) {
        save_packet_statement(context->header_db, &(el_packet->tp));
      }
      free_packet_tuple(&el_packet->tp);
      free_packet_queue_el(el_packet);
    }
  }

  if (context->file_write) {
    while(get_pcap_queue_length(context->cqueue)) {
      if ((el_pcap = pop_pcap_queue(context->cqueue)) != NULL) {
        if (save_pcap_file_data(&(el_pcap->header), el_pcap->packet, context) < 0) {
          log_trace("save_pcap_file_data fail");
        }
        free_pcap_queue_el(el_pcap);
      }
    }
  }

  if (context->db_sync) {
    if ((traces = concat_string_queue(context->squeue, context->sync_send_size)) != NULL) {
#ifdef WITH_SQLSYNC_SERVICE
      if (!run_sync_db_statement(context-> grpc_srv_addr, context->db_name, 1, traces)) {
        log_trace("run_sync_db_statement fail");
      }
#endif
      os_free(traces);
      empty_string_queue(context->squeue, context->sync_send_size);
    }
  }

  if (eloop_register_timeout(0, context->process_interval, eloop_tout_handler, (void *)NULL, (void *)context) == -1) {
    log_debug("eloop_register_timeout fail");
  }
}

void trace_callback(char *sqlite_statement, void *ctx)
{
  struct string_queue *squeue = (struct string_queue *)ctx;

  if (push_string_queue(squeue, sqlite_statement) == NULL) {
    log_trace("push_string_queue fail");
  }
}

int start_default_analyser(struct capture_conf *config)
{
  int ret = -1;
  struct capture_context context;
  char *header_db_path = NULL;
  char *pcap_db_path = NULL;

  os_memset(&context, 0, sizeof(context));
  generate_radom_uuid(context.cap_id);

  if (get_hostname(context.hostname) < 0) {
    log_debug("get_hostname fail");
    return -1;
  }
  // Transform to microseconds
  context.interface = config->capture_interface;
  context.filter = config->filter;
  context.process_interval = config->process_interval * 1000;
  context.file_write = config->file_write;
  context.db_write = config->db_write;
  context.db_sync = config->db_sync;
  context.db_path = config->db_path;
  context.sync_store_size = config->sync_store_size;
  context.sync_send_size = config->sync_send_size;

  if (strlen(config->db_sync_address)) {
    snprintf(context.grpc_srv_addr, MAX_WEB_PATH_LEN, "%s:%d", config->db_sync_address, config->db_sync_port);
  }

  construct_header_db_name(context.cap_id, context.db_name);
  header_db_path = construct_path(context.db_path, context.db_name);

  if (header_db_path == NULL) {
    log_debug("construct_path fail");
    return -1;
  }

  pcap_db_path = construct_path(context.db_path, PCAP_DB_NAME);
  if (pcap_db_path == NULL) {
    log_debug("construct_path fail");
    os_free(header_db_path);
    return -1;
  }
  
  log_info("Capturing hostname=%s", context.hostname);
  log_info("Capturing id=%s", context.cap_id);
  log_info("Capturing interface=%s", context.interface);
  log_info("Capturing filter=%s", context.filter);
  log_info("Promiscuous mode=%d", config->promiscuous);
  log_info("Immediate mode=%d", config->immediate);
  log_info("Buffer timeout=%d", config->buffer_timeout);
  log_info("Process interval=%d (milliseconds)", config->process_interval);
  log_info("Sync store size=%ld",   context.sync_store_size);
  log_info("Sync send size=%ld",   context.sync_send_size);
  log_info("File write=%d", context.file_write);
  log_info("DB write=%d", context.db_write);
  log_info("DB sync=%d", context.db_sync);
  log_info("DB name=%s", context.db_name);
  log_info("DB path=%s", header_db_path);
  log_info("GRPC Server address=%s", context.grpc_srv_addr);

  context.pqueue = init_packet_queue();

  if (context.pqueue == NULL) {
    log_debug("init_packet_queue fail");
    os_free(header_db_path);
    os_free(pcap_db_path);
    return -1;
  }

  context.cqueue = init_pcap_queue();

  if (context.cqueue == NULL) {
    log_debug("init_pcap_queue fail");
    os_free(header_db_path);
    os_free(pcap_db_path);
    free_packet_queue(context.pqueue);
    return -1;
  }

  context.squeue = init_string_queue(context.sync_store_size);
  if (context.squeue == NULL) {
    log_debug("init_string_queue fail");
    free_packet_queue(context.pqueue);
    free_pcap_queue(context.cqueue);
    return -1;
  }

  if (config->db_write) {
    if (config->db_sync) {
#ifdef WITH_SQLSYNC_SERVICE
      if (!run_register_db(context.grpc_srv_addr, context.db_name)) {
        log_trace("run_register_db fail");
      }

      ret = open_sqlite_header_db(header_db_path, trace_callback, (void*)context.squeue,
                                  (sqlite3 **)&context.header_db);
#else
      ret = open_sqlite_header_db(header_db_path, NULL, NULL,
                                                     (sqlite3 **)&context.header_db);
#endif
    } else {
      ret = open_sqlite_header_db(header_db_path, NULL, NULL,
                                                     (sqlite3 **)&context.header_db);
    }

    if (ret < 0) {
      log_debug("open_sqlite_header_db fail");
      free_packet_queue(context.pqueue);
      free_pcap_queue(context.cqueue);
      free_string_queue(context.squeue);
      os_free(header_db_path);
      os_free(pcap_db_path);
      return -1;
    }
  }

  if (config->file_write) {
    if (open_sqlite_pcap_db(pcap_db_path, (sqlite3**)&context.pcap_db) < 0) {
      log_debug("open_sqlite_pcap_db fail");
      free_packet_queue(context.pqueue);
      free_pcap_queue(context.cqueue);
      free_string_queue(context.squeue);
      os_free(header_db_path);
      os_free(pcap_db_path);
      free_sqlite_header_db(context.header_db);
      return -1;
    }
  }

  if (run_pcap(context.interface, config->immediate,
               config->promiscuous, (int)config->buffer_timeout,
               context.filter, true, pcap_callback, (void *)&context,
               (struct pcap_context**)&(context.pc)) < 0) {
    log_debug("run_pcap fail");
    free_packet_queue(context.pqueue);
    free_pcap_queue(context.cqueue);
    free_string_queue(context.squeue);
    os_free(header_db_path);
    os_free(pcap_db_path);
    free_sqlite_header_db(context.header_db);
    free_sqlite_pcap_db(context.pcap_db);
    return -1;    
  }

  if (eloop_init()) {
		log_debug("Failed to initialize event loop");
		close_pcap(context.pc);
    free_packet_queue(context.pqueue);
    free_pcap_queue(context.cqueue);
    free_string_queue(context.squeue);
    os_free(header_db_path);
    os_free(pcap_db_path);
    free_sqlite_header_db(context.header_db);
    free_sqlite_pcap_db(context.pcap_db);
    return -1;
	}

  if (context.pc != NULL) {
    if (eloop_register_read_sock((context.pc)->pcap_fd, eloop_read_fd_handler, (void*)NULL, (void *)&context) ==  -1) {
      log_debug("eloop_register_read_sock fail");
      goto fail;
    }
  } else {
    log_debug("Empty pcap context");
    goto fail;
  }

  if (eloop_register_timeout(0, context.process_interval, eloop_tout_handler, (void *)NULL, (void *)&context) == -1) {
    log_debug("eloop_register_timeout fail");
    goto fail;
  }

  eloop_run();
  log_info("Capture ended.");

	/* And close the session */
	close_pcap(context.pc);
  eloop_destroy();
  free_packet_queue(context.pqueue);
  free_pcap_queue(context.cqueue);
  free_string_queue(context.squeue);
  free_sqlite_header_db(context.header_db);
  free_sqlite_pcap_db(context.pcap_db);
  os_free(header_db_path);
  os_free(pcap_db_path);
  return 0;

fail:
	close_pcap(context.pc);
  eloop_destroy();
  free_packet_queue(context.pqueue);
  free_pcap_queue(context.cqueue);
  free_string_queue(context.squeue);
  free_sqlite_header_db(context.header_db);
  free_sqlite_pcap_db(context.pcap_db);
  os_free(header_db_path);
  os_free(pcap_db_path);
  return -1;
}
