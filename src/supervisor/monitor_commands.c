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
 * @file monitor_commands.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the monitor commands.
 */
#include <libgen.h>

#include "mac_mapper.h"
#include "supervisor.h"
#include "sqlite_fingerprint_writer.h"
#include "sqlite_alert_writer.h"
#include "sqlite_macconn_writer.h"
#include "network_commands.h"

#include "../ap/ap_config.h"
#include "../ap/ap_service.h"
#include "../crypt/crypt_service.h"
#include "../capture/capture_service.h"
#include "../capture/capture_config.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/base64.h"
#include "../utils/eloop.h"
#include "../utils/iptables.h"

static const UT_icd fingerprint_icd = {sizeof(struct fingerprint_row), NULL, NULL, NULL};

int set_fingerprint_cmd(struct supervisor_context *context, char *src_mac_addr,
                        char *dst_mac_addr, char *protocol, char *fingerprint,
                        uint64_t timestamp, char *query)
{
  struct fingerprint_row row_src = {.mac = src_mac_addr, .protocol = protocol,
                                .fingerprint = fingerprint, .timestamp = timestamp,
                                .query = query};

  struct fingerprint_row row_dst = {.mac = dst_mac_addr, .protocol = protocol,
                                .fingerprint = fingerprint, .timestamp = timestamp,
                                .query = query};

  log_trace("SET_FINGERPRINT for src_mac=%s, dst_mac=%s, protocol=%s and timestamp=%"PRIu64, src_mac_addr,
            dst_mac_addr, protocol, timestamp);
  if (save_sqlite_fingerprint_row(context->fingeprint_db, &row_src) < 0) {
    log_trace("save_sqlite_fingerprint_entry fail");
    return -1;
  }

  if (save_sqlite_fingerprint_row(context->fingeprint_db, &row_dst) < 0) {
    log_trace("save_sqlite_fingerprint_entry fail");
    return -1;
  }

  return 0;
}

void free_row_array(char *row_array[])
{
  int idx = 0;
  while(row_array[idx] != NULL) {
    os_free(row_array[idx]);
    idx ++;
  }
}

ssize_t query_fingerprint_cmd(struct supervisor_context *context, char *mac_addr, uint64_t timestamp,
                        char *op, char *protocol, char **out)
{
  UT_array *rows = NULL;
  ssize_t out_size = 0;
  struct fingerprint_row *p = NULL;
  char *row_array[6] = {}, *row;
  char *proto = (strcmp(protocol, "all") == 0) ? NULL : protocol;

  // Create the connections list
  utarray_new(rows, &fingerprint_icd);

  if (rows == NULL) {
    log_trace("utarray_new fail");
    return -1;
  }

  *out = NULL;
  log_trace("QUERY_FINGERPRINT for mac=%s, protocol=%s op=\"%s\" and timestamp=%"PRIu64, mac_addr,
            protocol, op, timestamp);
  if (get_sqlite_fingerprint_rows(context->fingeprint_db, mac_addr,
                                     timestamp, op, proto, rows) < 0)
  {
    log_trace("get_sqlite_fingerprint_rows fail");
    free_sqlite_fingerprint_rows(rows);
    return -1;
  }

  while((p = (struct fingerprint_row *) utarray_next(rows, p)) != NULL) {
    os_memset(row_array, 0, 6);

    if (p->mac != NULL) {
      row_array[0] = os_malloc(strlen(p->mac) + 2);
      if (row_array[0] == NULL) {
        log_err("os_malloc");
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }
      sprintf(row_array[0], "%s,", p->mac);
    } else {
      row_array[0] = os_malloc(2);
      if (row_array[0] == NULL) {
        log_err("os_malloc");
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }

      sprintf(row_array[0], ",");
    }

    if (p->protocol != NULL) {
      row_array[1] = os_malloc(strlen(p->protocol) + 2);
      if (row_array[1] == NULL) {
        log_err("os_malloc");
        free_row_array(row_array);
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }

      sprintf(row_array[1], "%s,", p->protocol);
    } else {
      row_array[1] = os_malloc(2);
      if (row_array[1] == NULL) {
        log_err("os_malloc");
        free_row_array(row_array);
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }
      sprintf(row_array[1], ",");
    }

    if (p->fingerprint != NULL) {
      row_array[2] = os_malloc(strlen(p->fingerprint) + 2);
      if (row_array[2] == NULL) {
        log_err("os_malloc");
        free_row_array(row_array);
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }

      sprintf(row_array[2], "%s,", p->fingerprint);
    } else {
      row_array[2] = os_malloc(2);
      if (row_array[2] == NULL) {
        log_err("os_malloc");
        free_row_array(row_array);
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }

      sprintf(row_array[2], ",");
    }

    row_array[3] = os_malloc(MAX_UINT64_DIGITS + 2);
    if (row_array[3] == NULL) {
      log_err("os_malloc");
      free_row_array(row_array);
      free_sqlite_fingerprint_rows(rows);
      if (*out != NULL) os_free(*out);
      return -1;
    }
    sprintf(row_array[3], "%"PRIu64",", p->timestamp);

    if (p->query != NULL) {
      row_array[4] = os_malloc(strlen(p->query) + 2);
      if (row_array[4] == NULL) {
        log_err("os_malloc");
        free_row_array(row_array);
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }
      sprintf(row_array[4], "%s\n", p->query);
    } else {
      row_array[4] = os_malloc(2);
      if (row_array[4] == NULL) {
        log_err("os_malloc");
        free_row_array(row_array);
        free_sqlite_fingerprint_rows(rows);
        if (*out != NULL) os_free(*out);
        return -1;
      }
      sprintf(row_array[4], "\n");
    }

    row = os_zalloc(strlen(row_array[0]) + strlen(row_array[1]) + strlen(row_array[2]) +
                    strlen(row_array[3]) + strlen(row_array[4]) + 1);

    if (row == NULL) {
      log_err("os_zalloc");
      free_row_array(row_array);
      free_sqlite_fingerprint_rows(rows);
      return -1;
    }

    for (int idx = 0; idx < 5; idx ++) {
      strcat(row, row_array[idx]);
    }

    free_row_array(row_array);

    if (*out == NULL) {
      out_size = strlen(row) + 1;
      *out = os_zalloc(out_size);
    } else {
      out_size += strlen(row);
      *out = os_realloc(*out, out_size);
    }

    if (*out == NULL) {
      log_trace("os_zalloc/os_realloc");
      os_free(row);
      free_sqlite_fingerprint_rows(rows);
      return -1;
    }

    strcat(*out, row);
    os_free(row);
  }

  free_sqlite_fingerprint_rows(rows);
  return out_size;
}

int set_alert_cmd(struct supervisor_context *context, struct alert_meta *meta,
                        uint8_t *info, size_t info_size)
{
  struct alert_row row;

  os_memset(&row, 0, sizeof(struct alert_row));

  log_trace("SET_ALERT for src_mac="MACSTR", dst_mac="MACSTR", and timestamp=%"PRIu64, MAC2STR(meta->src_mac_addr),
            MAC2STR(meta->dst_mac_addr), meta->timestamp);

  if ((row.hostname = os_strdup(meta->hostname)) == NULL) {
    log_err("os_strdup");
    return -1;
  }

  if ((row.analyser = os_strdup(meta->analyser)) == NULL) {
    log_err("os_strdup");
    free_sqlite_alert_row(&row);
    return -1;
  }

  if ((row.ifname = os_strdup(meta->ifname)) == NULL) {
    log_err("os_strdup");
    free_sqlite_alert_row(&row);
    return -1;
  }

  if ((row.src_mac_addr = os_zalloc(MACSTR_LEN)) == NULL) {
    log_err("os_zalloc");
    free_sqlite_alert_row(&row);
    return -1;
  }
  sprintf(row.src_mac_addr, MACSTR, MAC2STR(meta->src_mac_addr));

  if ((row.dst_mac_addr = os_zalloc(MACSTR_LEN)) == NULL) {
    log_err("os_zalloc");
    free_sqlite_alert_row(&row);
    return -1;
  }
  sprintf(row.dst_mac_addr, MACSTR, MAC2STR(meta->dst_mac_addr));

  row.timestamp = meta->timestamp;
  row.risk = meta->risk;

  if ((row.info = os_zalloc(info_size + 1)) == NULL) {
    log_err("os_zalloc");
    free_sqlite_alert_row(&row);
    return -1;
  }
  os_memcpy(row.info, info, info_size);

  if (save_sqlite_alert_row(context->alert_db, &row) < 0) {
    log_trace("save_sqlite_alert_row");
    free_sqlite_alert_row(&row);
    return -1;
  }
  free_sqlite_alert_row(&row);

  if (meta->risk >= context->risk_score) {
    log_trace("Moving mac="MACSTR" to quarantine vlanid=%d", MAC2STR(meta->src_mac_addr), context->quarantine_vlanid);
    if (accept_mac_cmd(context, meta->src_mac_addr, context->quarantine_vlanid) < 0) {
      log_trace("accept_mac_cmd fail");
      return -1;
    }
  }
  return 0;
}