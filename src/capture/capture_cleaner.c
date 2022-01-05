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
 * @file capture_cleaner.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the capture cleaner service structures.
 * 
 * Defines the start function for the capturte cleaner service, which
 * removes the capture files from the database folder when it 
 * reaches a given size specified in the capture_conf structure. The
 * store size is give by the parameter capture_store_size in Kb.
 */

#include <sqlite3.h>

#include "sqlite_pcap_writer.h"
#include "capture_config.h"

#include "../utils/eloop.h"
#include "../utils/utarray.h"

#define CLEANER_CHECK_INTERVAL  5        /* Frequency in sec to run the cleaner function*/
#define CLEANER_GROUP_INTERVAL  1000     /* Number of rows to sum from the pcap metadata to calculate the store size*/

static const UT_icd pcap_file_meta_icd = {sizeof(struct pcap_file_meta), NULL, NULL, NULL};

struct cleaner_context {
  sqlite3 *pcap_db;
  char pcap_path[MAX_OS_PATH_LEN];
  uint64_t store_size;
  uint64_t low_timestamp;
  uint64_t store_sum;
  uint64_t next_timestamp;
};

int clean_capture(struct cleaner_context *context)
{
  struct pcap_file_meta *p = NULL;
  UT_array *pcap_meta_arr = NULL;
  uint64_t timestamp = context->low_timestamp, lt;
  char *path; 
  utarray_new(pcap_meta_arr, &pcap_file_meta_icd);
  
  while(timestamp <= context->next_timestamp) {
    lt = timestamp;
    if (get_pcap_meta_array(context->pcap_db, timestamp, CLEANER_GROUP_INTERVAL, pcap_meta_arr) < 0) {
      log_trace("get_pcap_array fail");
      utarray_free(pcap_meta_arr);
      return -1;
    }

    while((p = (struct pcap_file_meta *) utarray_next(pcap_meta_arr, p)) != NULL) {
      if ((path = construct_path(context->pcap_path, p->name)) == NULL) {
        log_err("os_malloc");
      }

      log_trace("deleting %s at timestamp=%llu", path, p->timestamp);
      if (remove(path) < 0) {
        log_err("remove");
      }

      if (path != NULL) {
        os_free(path);
      }

      if (p->name != NULL) {
        os_free(p->name);
      }
      timestamp = p->timestamp;
    }
    utarray_clear(pcap_meta_arr);

    if (delete_pcap_entries(context->pcap_db, lt, timestamp) < 0) {
      log_trace("delete_pcap_entries fail");
      utarray_free(pcap_meta_arr);
      return -1;    
    }
  }

  utarray_free(pcap_meta_arr);
  return 0;
}

void eloop_cleaner_handler(void *eloop_ctx, void *user_ctx)
{
  (void) eloop_ctx;
  int res = 0;
  uint64_t lt, ht, sum = 0;
  uint64_t caplen = 0;
  struct cleaner_context *context = (struct cleaner_context *) user_ctx;

  lt = context->next_timestamp;

  if (!lt) {
    res = get_first_pcap_entry(context->pcap_db, &lt, &caplen);
    if (res < 0) {
      log_trace("get_first_pcap_entry fail");
    } else if (res > 0) {
      log_trace("No rows");
    }

    context->low_timestamp = lt;
    context->store_sum = caplen;
  }
  
  ht = lt;

  if (lt) {
    if (sum_pcap_group(context->pcap_db, lt, CLEANER_GROUP_INTERVAL, &ht, &sum) < 0) {
      log_trace("sum_pcap_group fail");
    } else {
      if (ht != lt) {
        context->store_sum += sum;
        context->next_timestamp = ht;
      }
    }
  }

  if (context->store_sum >= context->store_size) {
    log_trace("Started cleanup...");
    clean_capture(context);
    context->low_timestamp = 0;
    context->store_sum = 0;
    context->next_timestamp = 0;
  }

  if (eloop_register_timeout(CLEANER_CHECK_INTERVAL, 0, eloop_cleaner_handler, (void *)NULL, (void *)user_ctx) == -1) {
    log_debug("eloop_register_timeout fail");
  }
}

int start_capture_cleaner(struct capture_conf *config)
{
  struct cleaner_context context;

  char *pcap_db_path = NULL;
  char *pcap_subfolder_path = NULL;

  os_memset(&context, 0, sizeof(context));

  if (!config->capture_store_size) {
    log_trace("Nothing to clean");
    return 0;
  }

  if (!os_strnlen_s(config->db_path, MAX_OS_PATH_LEN)) {
    log_trace("db_path is empty");
    return -1;
  }

  // Transform to bytes
  context.store_size = (uint64_t)(config->capture_store_size) * 1024;

  if ((pcap_subfolder_path = construct_path(config->db_path, PCAP_SUBFOLDER_NAME)) == NULL) {
    log_trace("construct_path fail");
    return -1;
  }

  strcpy(context.pcap_path, pcap_subfolder_path);
  os_free(pcap_subfolder_path);

  if ((pcap_db_path = construct_path(config->db_path, PCAP_DB_NAME)) == NULL) {
    log_debug("construct_path fail");
    return -1;
  }

  log_info("Cleaning db_path=%s", config->db_path);
  log_info("Cleaning pcap_db_path=%s", pcap_db_path);
  log_info("Cleaning store_size=%llu bytes", context.store_size);

  if (open_sqlite_pcap_db(pcap_db_path, (sqlite3**)&context.pcap_db) < 0) {
    log_trace("open_sqlite_pcap_db fail");
    os_free(pcap_db_path);
    return -1;  
  }
  os_free(pcap_db_path);

  if (eloop_init()) {
    log_trace("eloop_init fail");
    free_sqlite_pcap_db(context.pcap_db);
    return -1;
  }

  if (eloop_register_timeout(CLEANER_CHECK_INTERVAL, 0, eloop_cleaner_handler, (void *)NULL, (void *)&context) == -1) {
    log_debug("eloop_register_timeout fail");
    free_sqlite_pcap_db(context.pcap_db);
    eloop_destroy();
    return -1;
  }

  eloop_run();
  log_info("Cleaning ended.");

  free_sqlite_pcap_db(context.pcap_db);
  eloop_destroy();
  return 0;
}
