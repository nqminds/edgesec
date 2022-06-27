/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the sqlite utilities.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "../utils/log.h"

int execute_sqlite_query(sqlite3 *db, char *statement) {
  char *err = NULL;
  int rc = sqlite3_exec(db, statement, 0, 0, &err);

  if (rc != SQLITE_OK) {
    log_error("Failed to execute statement %s", err);
    sqlite3_free(err);

    return -1;
  }

  return 0;
}

int check_table_exists(sqlite3 *db, char *table_name) {
  sqlite3_stmt *res;
  char *sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?;";
  int rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

  if (rc == SQLITE_OK)
    sqlite3_bind_text(res, 1, table_name, -1, NULL);
  else {
    log_error("Failed to execute statement: %s", sqlite3_errmsg(db));
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
