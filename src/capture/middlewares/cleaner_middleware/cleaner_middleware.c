/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the capture cleaner service
 * structures.
 *
 * Defines the start function for the capturte cleaner service, which
 * removes the capture files from the database folder when it
 * reaches a given size specified in the capture_conf structure. The
 * store size is give by the parameter CLEANER_STORE_SIZE in Kb.
 */

#include "./cleaner_middleware.h"

#include <libgen.h>
#include <sqlite3.h>
#include <utarray.h>

#include "../../capture_config.h"
#include "../../capture_service.h"
#include "../pcap_middleware/sqlite_pcap.h"

#include "../../../utils/allocs.h"
#include "../../../utils/os.h"

#include <eloop.h>

#define CLEANER_PROCESS_INTERVAL                                               \
  5 /* Frequency in sec to run the cleaner function*/
#define CLEANER_GROUP_INTERVAL                                                 \
  1024 /* Number of rows to sum from the pcap metadata to calculate the store  \
          size*/

#define CLEANER_STORE_SIZE 1000 /*Specifies the capture store size in KiB */

static const UT_icd pcap_file_meta_icd = {sizeof(struct pcap_file_meta), NULL,
                                          NULL, NULL};

struct cleaner_middleware_context {
  char pcap_path[MAX_OS_PATH_LEN];
  uint64_t store_size;
  uint64_t low_timestamp;
  uint64_t store_sum;
  uint64_t next_timestamp;
};

int clean_capture(struct middleware_context *context) {
  struct cleaner_middleware_context *cleaner_context =
      (struct cleaner_middleware_context *)context->mdata;

  struct pcap_file_meta *p = NULL;

  UT_array *pcap_meta_arr = NULL;
  uint64_t timestamp = cleaner_context->low_timestamp, lt;
  utarray_new(pcap_meta_arr, &pcap_file_meta_icd);

  while (timestamp <= cleaner_context->next_timestamp) {
    lt = timestamp;
    if (get_pcap_meta_array(context->db, timestamp, CLEANER_GROUP_INTERVAL,
                            pcap_meta_arr) < 0) {
      log_error("get_pcap_array fail");
      utarray_free(pcap_meta_arr);
      return -1;
    }

    while ((p = (struct pcap_file_meta *)utarray_next(pcap_meta_arr, p)) !=
           NULL) {
      char *const path = construct_path(cleaner_context->pcap_path, p->name);
      if (path == NULL) {
        log_errno("os_malloc");
      }

      log_trace("deleting %s at timestamp=%" PRIu64, path, p->timestamp);
      if (remove(path) < 0) {
        log_errno("remove");
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

    if (delete_pcap_entries(context->db, lt, timestamp) < 0) {
      log_error("delete_pcap_entries fail");
      utarray_free(pcap_meta_arr);
      return -1;
    }
  }

  utarray_free(pcap_meta_arr);
  return 0;
}

void eloop_tout_cleaner_handler(void *eloop_ctx, void *user_ctx) {
  (void)eloop_ctx;

  struct middleware_context *context = (struct middleware_context *)user_ctx;
  struct cleaner_middleware_context *cleaner_context =
      (struct cleaner_middleware_context *)context->mdata;

  int res = 0;
  uint64_t lt, ht, sum = 0;
  uint64_t caplen = 0;

  lt = cleaner_context->next_timestamp;

  if (!lt) {
    res = get_first_pcap_entry(context->db, &lt, &caplen);
    if (res < 0) {
      log_error("get_first_pcap_entry fail");
    } else if (res > 0) {
      log_trace("No rows");
    }

    cleaner_context->low_timestamp = lt;
    cleaner_context->store_sum = caplen;
  }

  ht = lt;

  if (lt) {
    if (sum_pcap_group(context->db, lt, CLEANER_GROUP_INTERVAL, &ht, &sum) <
        0) {
      log_trace("sum_pcap_group fail");
    } else if (ht != lt) {
      cleaner_context->store_sum += sum;
      cleaner_context->next_timestamp = ht;
    }
  }

  if (cleaner_context->store_sum >= cleaner_context->store_size) {
    log_trace("Started cleanup...");
    clean_capture(context);
    cleaner_context->low_timestamp = 0;
    cleaner_context->store_sum = 0;
    cleaner_context->next_timestamp = 0;
  }

  if (edge_eloop_register_timeout(context->eloop, CLEANER_PROCESS_INTERVAL, 0,
                                  eloop_tout_cleaner_handler, NULL,
                                  (void *)user_ctx) == -1) {
    log_error("edge_eloop_register_timeout fail");
  }
}

void free_cleaner_middleware(struct middleware_context *context) {
  struct cleaner_middleware_context *cleaner_context;

  if (context != NULL) {
    if (context->mdata != NULL) {
      cleaner_context = (struct cleaner_middleware_context *)context->mdata;
      os_free(cleaner_context);
      context->mdata = NULL;
    }
    os_free(context);
  }
}

struct middleware_context *init_cleaner_middleware(sqlite3 *db, char *db_path,
                                                   struct eloop_data *eloop,
                                                   struct pcap_context *pc,
                                                   char *params) {
  log_info("Init cleaner middleware...");

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

  struct middleware_context *context =
      os_zalloc(sizeof(struct middleware_context));

  if (context == NULL) {
    log_errno("zalloc");
    return NULL;
  }

  struct cleaner_middleware_context *cleaner_context =
      os_zalloc(sizeof(struct cleaner_middleware_context));
  if (cleaner_context == NULL) {
    log_errno("zalloc");
    free_cleaner_middleware(context);
    return NULL;
  }

  context->db = db;
  context->eloop = eloop;
  context->pc = pc;
  context->mdata = (void *)cleaner_context;
  context->params = params;

  if (get_pcap_folder_path(db_path, cleaner_context->pcap_path) < 0) {
    log_error("get_pcap_folder_path fail");
    free_cleaner_middleware(context);
    return NULL;
  }

  // Transform to bytes
  cleaner_context->store_size = (uint64_t)(CLEANER_STORE_SIZE)*1024;

  log_info("Cleaning db_path=%s", db_path);
  log_info("Cleaning pcap_path=%s", cleaner_context->pcap_path);
  log_info("Cleaning store_size=%" PRIu64 " bytes",
           cleaner_context->store_size);

  if (edge_eloop_register_timeout(eloop, CLEANER_PROCESS_INTERVAL, 0,
                                  eloop_tout_cleaner_handler, NULL,
                                  (void *)context) == -1) {
    log_error("edge_eloop_register_timeout fail");
    free_cleaner_middleware(context);
    return NULL;
  }

  return context;
}

int process_cleaner_middleware(struct middleware_context *context,
                               const char *ltype, struct pcap_pkthdr *header,
                               uint8_t *packet, char *ifname) {
  (void)context;
  (void)ltype;
  (void)header;
  (void)packet;
  (void)ifname;

  return 0;
}

struct capture_middleware cleaner_middleware = {
    .init = init_cleaner_middleware,
    .process = process_cleaner_middleware,
    .free = free_cleaner_middleware,
    .name = "cleaner middleware",
};
