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
 * @file sqlite_alert_writer.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the sqlite alert writer utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sqlite3.h>

#include "sqlite_alert_writer.h"

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/sqliteu.h"

void free_sqlite_alert_db(sqlite3 *db)
{
  if (db != NULL) {
    sqlite3_close(db);
  }
}

int open_sqlite_alert_db(char *db_path, sqlite3** sql)
{
  sqlite3 *db = NULL;
  int rc;

  if ((rc = sqlite3_open(db_path, &db)) != SQLITE_OK) {
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  *sql = db;

  rc = check_table_exists(db, ALERT_TABLE_NAME);

  if (rc == 0) {
    log_debug("%s table doesn't exist creating...", ALERT_TABLE_NAME);
    if (execute_sqlite_query(db, ALERT_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_alert_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_alert_db(db);
    return -1;
  }

  return 0;
}

int save_sqlite_alert_row(sqlite3 *db, struct alert_row *row)
{
  sqlite3_stmt *res = NULL;
  int column_idx;

  if (row == NULL) {
    log_trace("row param is NULL");
    return -1;
  }

  if (sqlite3_prepare_v2(db, ALERT_INSERT_INTO, -1, &res, 0) != SQLITE_OK) {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@hostname");
  if (sqlite3_bind_text(res, column_idx, row->hostname, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@analyser");
  if (sqlite3_bind_text(res, column_idx, row->analyser, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@ifname");
  if (sqlite3_bind_text(res, column_idx, row->ifname, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@src_mac_addr");
  if (sqlite3_bind_text(res, column_idx, row->src_mac_addr, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@dst_mac_addr");
  if (sqlite3_bind_text(res, column_idx, row->dst_mac_addr, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
  if (sqlite3_bind_int64(res, column_idx, row->timestamp) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@risk");
  if (sqlite3_bind_int64(res, column_idx, row->risk) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@info");
  if (sqlite3_bind_text(res, column_idx, row->info, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  sqlite3_step(res);
  sqlite3_finalize(res);

  return 0;
}

void free_sqlite_alert_row(struct alert_row *row)
{
  if (row != NULL) {
    if (row->hostname != NULL) os_free(row->hostname);
    if (row->analyser != NULL) os_free(row->analyser);
    if (row->ifname != NULL) os_free(row->ifname);
    if (row->src_mac_addr != NULL) os_free(row->src_mac_addr);
    if (row->dst_mac_addr != NULL) os_free(row->dst_mac_addr);
    if (row->info != NULL) os_free(row->info);
  }
}
