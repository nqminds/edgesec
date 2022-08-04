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

#define SQLITE_EXEC_TRIES 10000

int execute_sqlite_query(sqlite3 *db, const char *statement) {
  int rc = sqlite3_exec(db, statement, 0, 0, NULL);

  if (rc != SQLITE_OK) {
    log_error("Failed to execute statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int check_table_exists(sqlite3 *db, const char *table_name) {
  sqlite3_stmt *res = NULL;

  const char *sql =
      "SELECT name FROM sqlite_master WHERE type='table' AND name=?;";
  if (sqlite3_prepare_v2(db, sql, -1, &res, 0) != SQLITE_OK) {
    log_trace("Preparing %s failed due to %s", sql, sqlite3_errmsg(db));
    return -1;
  }

  if (sqlite3_bind_text(res, 1, table_name, -1, SQLITE_STATIC) != SQLITE_OK) {
    log_trace("Binding params failed due to %s", sqlite3_errmsg(db));
    return -1;
  }

  switch (sqlite3_step(res)) {
    case SQLITE_ROW:
      log_trace("Found table %s", sqlite3_column_text(res, 0));
      sqlite3_finalize(res);
      return 1;
    case SQLITE_DONE:
      sqlite3_finalize(res);
      return 0;
    default:
      log_error("Failed to get results: %s", sqlite3_errmsg(db));
      sqlite3_finalize(res);
      return -1;
  }
}
