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
 * @file sqliteu.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the sqlite utilities.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "../utils/log.h"

int execute_sqlite_query(sqlite3 *db, char *statement)
{
  char *err = NULL;
  int rc = sqlite3_exec(db, statement, 0, 0, &err);

  if (rc != SQLITE_OK ) {
    log_trace("Failed to execute statement %s", err);
    sqlite3_free(err);

    return -1;
  }

  return 0;
}

int check_table_exists(sqlite3 *db, char *table_name)
{
  sqlite3_stmt *res;
  char *sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?;";
  int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);


  if (rc == SQLITE_OK)
    sqlite3_bind_text(res, 1, table_name, -1, NULL);
  else {
    log_trace("Failed to execute statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  log_trace("%s", sql);
  rc = sqlite3_step(res);

  if (rc == SQLITE_ROW) {
    log_trace("Found table %s", sqlite3_column_text(res, 0));
    sqlite3_finalize(res);
    return 1;
  }

  sqlite3_finalize(res);
  return 0;
}
