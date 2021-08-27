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
 * @file sqlite_fingerprint_writer.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the sqlite fingerprint writer utilities.
 */

#ifndef SQLITE_FINGERPRINT_WRITER_H
#define SQLITE_FINGERPRINT_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/squeue.h"

#define FINGERPRINT_TABLE_NAME "fingerprint"
#define FINGERPRINT_CREATE_TABLE "CREATE TABLE " FINGERPRINT_TABLE_NAME " (mac TEXT NOT NULL, protocol TEXT, fingerprint TEXT, " \
                                 "timestamp INTEGER NOT NULL, query TEXT, PRIMARY KEY (mac, timestamp));"
#define FINGERPRINT_INSERT_INTO "INSERT INTO " FINGERPRINT_TABLE_NAME " VALUES(@mac, @protocol, @fingerprint, @timestamp, @query);"
#define FINGERPRINT_SELECT_FROM_NO_PROTO "SELECT mac, protocol, fingerprint, timestamp, query FROM " FINGERPRINT_TABLE_NAME \
                                         " WHERE mac=@mac AND timestamp%.2s@timestamp;"
#define FINGERPRINT_SELECT_FROM_PROTO "SELECT mac, protocol, fingerprint, timestamp, query FROM " FINGERPRINT_TABLE_NAME \
                                      " WHERE mac=@mac AND timestamp%.2s@timestamp AND protocol LIKE @protocol;"

/**
 * @brief The fingerprint row definition
 * 
 */
struct fingerprint_row {
  char *mac;                /**< The MAC */
  char *protocol;           /**< The protocol idenitifier */
  char *fingerprint;        /**< The fingerprint */
  uint64_t timestamp;       /**< The timestamp */
  char *query;              /**< The query string */
};

/**
 * @brief Opens the sqlite fingerprint db
 * 
 * @param db_path The sqlite db path
 * @param sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_fingerprint_db(char *db_path, sqlite3** sql);

/**
 * @brief Closes the sqlite db
 * 
 * @param ctx The sqlite db structure pointer
 */
void free_sqlite_fingerprint_db(sqlite3 *db);

/**
 * @brief Save a fingerprint row into the sqlite db
 * 
 * @param db The sqlite db structure pointer
 * @param row The entry row
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_fingerprint_row(sqlite3 *db, struct fingerprint_row *row);


/**
 * @brief Retrieves all the fingerprint rows satifying a query
 * 
 * @param db The sqlite db structure pointer
 * @param mac The MAC value for
 * @param timestamp The timestamp value
 * @param op The timestamp operator value
 * @param protocol The protocol value (if NULL returns all the protocols)
 * @param rows The output rows
 * @return int 0 on success, -1 on failure
 */
int get_sqlite_fingerprint_rows(sqlite3 *db, char *mac, uint64_t timestamp, char *op,
                                   char *protocol, UT_array *rows);

/**
 * @brief Frees all the rows an an array of rows
 * 
 * @param rows The array of rows
 */
void free_sqlite_fingerprint_rows(UT_array *rows);

#endif
