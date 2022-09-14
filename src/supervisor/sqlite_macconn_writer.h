/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the sqlite macconn writer utilities.
 */

#ifndef SQLITE_MACCONN_WRITER_H
#define SQLITE_MACCONN_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

#include "mac_mapper.h"

#include <utarray.h>
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/squeue.h"

#define MACCONN_TABLE_NAME "instance"

#define MACCONN_CREATE_TABLE                                                   \
  "CREATE TABLE IF NOT EXISTS " MACCONN_TABLE_NAME                             \
  " (id TEXT NOT NULL, mac TEXT NOT NULL, status INTEGER, vlanid INTEGER, "    \
  "primaryip TEXT, secondaryip TEXT, nat INTEGER, allow INTEGER, label TEXT, " \
  "timestamp INTEGER, pass TEXT, PRIMARY KEY (id, mac));"
#define MACCONN_INSERT_INTO                                                    \
  "INSERT INTO " MACCONN_TABLE_NAME                                            \
  " VALUES(@id, @mac, @status, @vlanid, @primaryip, @secondaryip, "            \
  "@nat, @allow, @label, @timestamp, @pass);"
#define MACCONN_DELETE_FROM "DELETE FROM " MACCONN_TABLE_NAME " WHERE mac=@mac;"
#define MACCONN_SELECT_FROM                                                    \
  "SELECT mac, id, status, vlanid, nat, allow, label, pass FROM "              \
  " " MACCONN_TABLE_NAME ";"

/**
 * @brief Opens the sqlite macconn db
 *
 * @param db_path The sqlite db path
 * @param[out] sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_macconn_db(const char *db_path, sqlite3 **sql);

/**
 * @brief Closes the sqlite db
 *
 * @param db The sqlite db structure pointer
 */
void free_sqlite_macconn_db(sqlite3 *db);

/**
 * @brief Saves a macconn entry in the sqlite db
 *
 * @param db The sqlite db structure pointer
 * @param conn The MAC connection structure
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_macconn_entry(sqlite3 *db, struct mac_conn *conn);

/**
 * @brief Saves a macconn entries in the sqlite db
 *
 * @param db The sqlite db structure pointer
 * @param entries The macconn entries
 * @return int 0 on success, -1 on failure
 */
int get_sqlite_macconn_entries(sqlite3 *db, UT_array *entries);

#endif
