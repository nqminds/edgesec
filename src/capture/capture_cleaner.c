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
 */

#include <sqlite3.h>

#include "sqlite_pcap_writer.h"
#include "capture_config.h"

#include "../utils/eloop.h"

#define CLEANER_CHECK_INTERVAL 1       // Interval in sec

struct cleaner_context {
  sqlite3 *pcap_db;
  char pcap_path[MAX_OS_PATH_LEN];
  uint64_t store_size;
};

void eloop_cleaner_handler(void *eloop_ctx, void *user_ctx)
{
  (void) eloop_ctx;
  int res = 0;
  uint64_t timestamp = 0;
  struct cleaner_context *context = (struct cleaner_context *) user_ctx;

  res = get_first_pcap_entry(context->pcap_db, &timestamp);
  if (res < 0) {
    log_trace("get_first_pcap_entry fail");
  } else if (res > 0) {
    log_trace("No rows");
  }
  
  log_trace("timestamp=%llu", timestamp);
  if (eloop_register_timeout(CLEANER_CHECK_INTERVAL, 0, eloop_cleaner_handler, (void *)NULL, (void *)&context) == -1) {
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
  log_info("Cleaning pcap_path=%s", context.pcap_path);
  log_info("Cleaning store_size=%llu", context.store_size);
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
