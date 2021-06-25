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

int save_sqlite_fingerprint_entry(sqlite3 *db, char *mac, char *protocol, char *fingerprint)
{
  sqlite3_stmt *res = NULL;
  int column_idx;

  if (sqlite3_prepare_v2(db, FINGERPRINT_INSERT_INTO, -1, &res, 0) != SQLITE_OK) {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@mac");
  if (sqlite3_bind_text(res, column_idx, mac, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@protocol");
  if (sqlite3_bind_text(res, column_idx, protocol, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  column_idx = sqlite3_bind_parameter_index(res, "@fingerprint");
  if (sqlite3_bind_text(res, column_idx, fingerprint, -1, NULL) != SQLITE_OK) {
    log_trace("sqlite3_bind_text fail");
    sqlite3_finalize(res);
    return -1;
  }

  sqlite3_step(res);
  sqlite3_finalize(res);

  return 0;
}
