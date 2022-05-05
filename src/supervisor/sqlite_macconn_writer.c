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
 * @file sqlite_macconn_writer.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the sqlite macconn writer
 * utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sqlite3.h>

#include "sqlite_macconn_writer.h"

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/sqliteu.h"
#include "../utils/utarray.h"

void free_sqlite_macconn_db(sqlite3 *db) {
  if (db != NULL) {
    sqlite3_close(db);
  }
}

int open_sqlite_macconn_db(char *db_path, sqlite3 **sql) {
  sqlite3 *db = NULL;
  int rc;

  if ((rc = sqlite3_open(db_path, &db)) != SQLITE_OK) {
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  *sql = db;

  rc = check_table_exists(db, MACCONN_TABLE_NAME);

  if (rc == 0) {
    log_debug("%s table doesn't exist creating...", MACCONN_TABLE_NAME);
    if (execute_sqlite_query(db, MACCONN_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_macconn_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_macconn_db(db);
    return -1;
  }

  return 0;
}

int save_sqlite_macconn_entry(sqlite3 *db, struct mac_conn *conn) {
  sqlite3_stmt *res = NULL;
  int column_idx;
  char mac_buf[MACSTR_LEN];

  if (conn == NULL) {
    log_trace("conn param is NULL");
    return -1;
  }

  snprintf(mac_buf, MACSTR_LEN, MACSTR, MAC2STR(conn->mac_addr));

  if (sqlite3_prepare_v2(db, MACCONN_DELETE_FROM, -1, &res, 0) != SQLITE_OK) {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@mac");
  if (sqlite3_bind_text(res, column_idx, mac_buf, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  sqlite3_step(res);
  sqlite3_finalize(res);

  if (sqlite3_prepare_v2(db, MACCONN_INSERT_INTO, -1, &res, 0) != SQLITE_OK) {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@id");
  if (sqlite3_bind_text(res, column_idx, conn->info.id, -1, NULL) !=
      SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@mac");
  if (sqlite3_bind_text(res, column_idx, mac_buf, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@status");
  if (sqlite3_bind_int(res, column_idx, conn->info.status) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@vlanid");
  if (sqlite3_bind_int(res, column_idx, conn->info.vlanid) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@primaryip");
  if (sqlite3_bind_text(res, column_idx, conn->info.ip_addr, -1, NULL) !=
      SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@secondaryip");
  if (sqlite3_bind_text(res, column_idx, conn->info.ip_sec_addr, -1, NULL) !=
      SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@nat");
  if (sqlite3_bind_int(res, column_idx, conn->info.nat) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@allow");
  if (sqlite3_bind_int(res, column_idx, conn->info.allow_connection) !=
      SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@label");
  if (sqlite3_bind_text(res, column_idx, conn->info.label, -1, NULL) !=
      SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
  if (sqlite3_bind_int64(res, column_idx, conn->info.join_timestamp) !=
      SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  sqlite3_step(res);
  sqlite3_finalize(res);

  return 0;
}

int get_sqlite_macconn_entries(sqlite3 *db, UT_array *entries) {
  sqlite3_stmt *res;
  int rc;
  struct mac_conn el;
  uint8_t mac_addr[ETH_ALEN];
  char *value;

  if (entries == NULL) {
    log_trace("entries param is NULL");
    return -1;
  }

  if (sqlite3_prepare_v2(db, MACCONN_SELECT_FROM, -1, &res, 0) != SQLITE_OK) {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
    os_memset(&el.info, 0, sizeof(el.info));

    // mac
    if (hwaddr_aton2((char *)sqlite3_column_text(res, 0), mac_addr) == -1) {
      log_trace("hwaddr_aton2 fail");
      sqlite3_finalize(res);
      return -1;
    }

    os_memcpy(el.mac_addr, mac_addr, ETH_ALEN);

    // id
    if ((value = (char *)sqlite3_column_text(res, 1)) != NULL) {
      os_strlcpy(el.info.id, value, MAX_RANDOM_UUID_LEN);
    }

    // status
    el.info.status = sqlite3_column_int(res, 2);

    // vlanid
    el.info.vlanid = sqlite3_column_int(res, 3);

    // nat
    el.info.nat = sqlite3_column_int(res, 4);

    // allow
    el.info.allow_connection = sqlite3_column_int(res, 5);

    // label
    if ((value = (char *)sqlite3_column_text(res, 6)) != NULL) {
      os_strlcpy(el.info.label, value, MAX_DEVICE_LABEL_SIZE);
    }

    utarray_push_back(entries, &el);
  }

  sqlite3_finalize(res);
  return 0;
}
