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
 * @file sqlite_macconn_writer.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the sqlite macconn writer utilities.
 */

#ifndef SQLITE_MACCONN_WRITER_H
#define SQLITE_MACCONN_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

#include "mac_mapper.h"

#include "../utils/utarray.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/squeue.h"

#define MACCONN_TABLE_NAME "instance"

#define MACCONN_CREATE_TABLE                                                   \
  "CREATE TABLE " MACCONN_TABLE_NAME                                           \
  " (id TEXT NOT NULL, mac TEXT NOT NULL, status INTEGER, vlanid INTEGER, "    \
  "primaryip TEXT, secondaryip TEXT, nat INTEGER, allow INTEGER, label TEXT, " \
  "timestamp INTEGER, PRIMARY KEY (id, mac));"
#define MACCONN_INSERT_INTO                                                    \
  "INSERT INTO " MACCONN_TABLE_NAME                                            \
  " VALUES(@id, @mac, @status, @vlanid, @primaryip, @secondaryip, "            \
  "@nat, @allow, @label, @timestamp);"
#define MACCONN_DELETE_FROM "DELETE FROM " MACCONN_TABLE_NAME " WHERE mac=@mac;"
#define MACCONN_SELECT_FROM                                                    \
  "SELECT mac, id, status, vlanid, nat, allow, label FROM "                    \
  " " MACCONN_TABLE_NAME ";"

/**
 * @brief Opens the sqlite macconn db
 *
 * @param db_path The sqlite db path
 * @param sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_macconn_db(char *db_path, sqlite3 **sql);

/**
 * @brief Closes the sqlite db
 *
 * @param ctx The sqlite db structure pointer
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
