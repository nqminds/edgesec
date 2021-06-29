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
 * @file sqlite_fingerprint_writer.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the sqlite fingerprint writer utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sqlite3.h>

#include "sqlite_fingerprint_writer.h"

#include "../utils/os.h"
#include "../utils/log.h"
#include "../utils/sqliteu.h"

void free_sqlite_fingerprint_db(sqlite3 *db)
{
  if (db != NULL) {
    sqlite3_close(db);
  }
}

int open_sqlite_fingerprint_db(char *db_path, sqlite3** sql)
{
  sqlite3 *db = NULL;
  int rc;
  
  if ((rc = sqlite3_open(db_path, &db)) != SQLITE_OK) {     
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  *sql = db;

  rc = check_table_exists(db, FINGERPRINT_TABLE_NAME);

  if (rc == 0) {
    log_debug("%s table doesn't exist creating...", FINGERPRINT_TABLE_NAME);
    if (execute_sqlite_query(db, FINGERPRINT_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_fingerprint_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_fingerprint_db(db);
    return -1;
  }

  return 0;
}

int save_sqlite_fingerprint_entry(sqlite3 *db, struct fingerprint_row *row)
{
  sqlite3_stmt *res = NULL;
  int column_idx;

  if (row == NULL) {
    log_trace("row param is NULL");
    return -1;
  }

  if (sqlite3_prepare_v2(db, FINGERPRINT_INSERT_INTO, -1, &res, 0) != SQLITE_OK) {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@mac");
  if (sqlite3_bind_text(res, column_idx, row->mac, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@protocol");
  if (sqlite3_bind_text(res, column_idx, row->protocol, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@fingerprint");
  if (sqlite3_bind_text(res, column_idx, row->fingerprint, -1, NULL) != SQLITE_OK) {
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

  column_idx = sqlite3_bind_parameter_index(res, "@query");
  if (sqlite3_bind_text(res, column_idx, row->query, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  sqlite3_step(res);
  sqlite3_finalize(res);

  return 0;
}

void free_sqlite_fingerprint_row_els(struct fingerprint_row *row)
{
  if (row != NULL) {
    if (row->mac != NULL) os_free(row->mac);
    if (row->fingerprint != NULL) os_free(row->fingerprint);
    if (row->protocol != NULL) os_free(row->protocol);
    if (row->query != NULL) os_free(row->query);
  }
}

int get_sqlite_fingerprint_entries(sqlite3 *db, char *mac, uint64_t timestamp, char *op,
                                   char *protocol, UT_array *entries)
{
  sqlite3_stmt *res = NULL;
  struct fingerprint_row row;
  int column_idx;
  int rc;
  char *sql_statement = (protocol == NULL) ? FINGERPRINT_SELECT_FROM_NO_PROTO : FINGERPRINT_SELECT_FROM_PROTO;
  char *statement;
  char *proto;
  char *value;

  if (entries == NULL) {
    log_trace("entries param is NULL");
    return -1;
  }

  if (op == NULL) {
    log_trace("op param is NULL");
    return -1;
  }

  statement = os_malloc(strlen(sql_statement) + 3);
  if (statement == NULL) {
    log_err("os_malloc");
    return -1;
  }

  sprintf(statement, sql_statement, op);

  if (protocol == NULL) {
    proto = protocol;
  } else {
    proto = os_malloc(strlen(protocol) + 3);
    if (proto == NULL) {
      log_err("os_malloc");
      os_free(statement);
      return -1;
    }
    sprintf(proto, "%c%s%c", '%', protocol, '%');
  }

  if (sqlite3_prepare_v2(db, statement, -1, &res, 0) != SQLITE_OK) {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    os_free(statement);
    if (proto != NULL) os_free(proto);
    return -1;
  }

  log_trace(statement);

  column_idx = sqlite3_bind_parameter_index(res, "@mac");
  if (sqlite3_bind_text(res, column_idx, mac, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    os_free(statement);
    if (proto != NULL) os_free(proto);
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
  if (sqlite3_bind_int64(res, column_idx, timestamp) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    os_free(statement);
    if (proto != NULL) os_free(proto);
    sqlite3_finalize(res);
    return -1;
  }

  if (proto != NULL) {
    column_idx = sqlite3_bind_parameter_index(res, "@protocol");
    if (sqlite3_bind_text(res, column_idx, proto, -1, NULL) != SQLITE_OK) {
      log_trace("sqlite3_bind_text fail");
      os_free(statement);
      if (proto != NULL) os_free(proto);
      sqlite3_finalize(res);
      return -1;
    }
  }

  while((rc = sqlite3_step(res)) == SQLITE_ROW) {
    os_memset(&row, 0, sizeof(row));

    value = (unsigned char*) sqlite3_column_text(res, 0);
    if (value != NULL) {
      row.mac = os_strdup(value);
      if (row.mac == NULL) {
        log_err("os_strdup");
        os_free(statement);
        if (proto != NULL) os_free(proto);
        sqlite3_finalize(res);
        return -1;
      }
    }

    value = (unsigned char*) sqlite3_column_text(res, 1);
    if (value != NULL) {
      row.protocol = os_strdup(value);
      if (row.protocol == NULL) {
        log_err("os_strdup");
        free_sqlite_fingerprint_row_els(&row);
        os_free(statement);
        if (proto != NULL) os_free(proto);
        sqlite3_finalize(res);
        return -1;
      }
    }

    value = (unsigned char*) sqlite3_column_text(res, 2);
    if (value != NULL) {
      row.fingerprint = os_strdup(value);
      if (row.fingerprint == NULL) {
        log_err("os_strdup");
        free_sqlite_fingerprint_row_els(&row);
        os_free(statement);
        if (proto != NULL) os_free(proto);
        sqlite3_finalize(res);
        return -1;
      }
    }

    row.timestamp = sqlite3_column_int64(res, 3);

    value = (unsigned char*) sqlite3_column_text(res, 4);
    if (value != NULL) {
      row.query = os_strdup(value);
      if (row.query == NULL) {
        log_err("os_strdup");
        free_sqlite_fingerprint_row_els(&row);
        os_free(statement);
        if (proto != NULL) os_free(proto);
        sqlite3_finalize(res);
        return -1;
      }
    }

    utarray_push_back(entries, &row);
  }


  os_free(statement);
  if (proto != NULL) os_free(proto);
  sqlite3_finalize(res);

  return 0;
}