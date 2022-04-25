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
 * @file sqlite_alert_writer.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the sqlite alert writer utilities.
 */

#ifndef SQLITE_ALERT_WRITER_H
#define SQLITE_ALERT_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/squeue.h"

#define ALERT_TABLE_NAME "alert"
#define ALERT_CREATE_TABLE                                                     \
  "CREATE TABLE " ALERT_TABLE_NAME                                             \
  " (hostname TEXT NOT NULL, analyser TEXT, ifname TEXT, src_mac_addr TEXT, "  \
  "dst_mac_addr TEXT, "                                                        \
  "timestamp INTEGER NOT NULL, risk INTEGER NOT NULL, info TEXT, PRIMARY KEY " \
  "(hostname, timestamp));"
#define ALERT_INSERT_INTO                                                      \
  "INSERT INTO " ALERT_TABLE_NAME                                              \
  " VALUES(@hostname, @analyser, @ifname, @src_mac_addr, @dst_mac_addr, "      \
  "@timestamp, @risk, @info);"

/**
 * @brief The alert row definition
 *
 */
struct alert_row {
  char *hostname;     /**< The machine hostname */
  char *analyser;     /**< The analyser type */
  char *ifname;       /**< The monitoring interface */
  char *src_mac_addr; /**< The source mac address */
  char *dst_mac_addr; /**< The destination mac address */
  uint64_t timestamp; /**< The timestamp value */
  uint64_t risk;      /**< The risk value */
  char *info;         /**< The info string */
};

/**
 * @brief Opens the sqlite alert db
 *
 * @param db_path The sqlite db path
 * @param sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_alert_db(char *db_path, sqlite3 **sql);

/**
 * @brief Closes the sqlite db
 *
 * @param ctx The sqlite db structure pointer
 */
void free_sqlite_alert_db(sqlite3 *db);

/**
 * @brief Frees a row element
 *
 * @param row The row structure
 */
void free_sqlite_alert_row(struct alert_row *row);

/**
 * @brief Save an alert row into the sqlite db
 *
 * @param db The sqlite db structure pointer
 * @param row The entry row
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_alert_row(sqlite3 *db, struct alert_row *row);

#endif
