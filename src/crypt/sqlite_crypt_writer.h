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
 * @file sqlite_crypt_writer.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the sqlite crypt writer utilities.
 */

#ifndef SQLITE_CRYPT_WRITER_H
#define SQLITE_CRYPT_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

#include "../utils/os.h"
#include "../utils/squeue.h"

#define CRYPT_TABLE_NAME "crypt"
#define CRYPT_CREATE_TABLE "CREATE TABLE " CRYPT_TABLE_NAME " (key TEXT NOT NULL, value TEXT, " \
                                 "PRIMARY KEY (key));"
#define CRYPT_INSERT_INTO "INSERT INTO " CRYPT_TABLE_NAME " VALUES(@key, @value);"

/**
 * @brief Opens the sqlite crypt db
 * 
 * @param db_path The sqlite db path
 * @param sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_crypt_db(char *db_path, sqlite3** sql);

/**
 * @brief Closes the sqlite db
 * 
 * @param ctx The sqlite db structure pointer
 */
void free_sqlite_crypt_db(sqlite3 *db);

/**
 * @brief Save a crypt entry into the sqlite db
 * 
 * @param db The sqlite db structure pointer
 * @param key The key string
 * @param value The value string
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_crypt_entry(sqlite3 *db, char *key, char *value);
#endif
