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
 * @file sqlite_meta_writer.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the sqlite meta writer utilities.
 */

#ifndef SQLITE_META_WRITER_H
#define SQLITE_META_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

#include "../utils/os.h"
#include "../utils/squeue.h"

#define META_CREATE_TABLE "CREATE TABLE meta (timestamp INTEGER NOT NULL, name TEXT, caplen INTEGER, length INTEGER, " \
                         "PRIMARY KEY (timestamp, name));"

#define META_INSERT_INTO "INSERT INTO meta VALUES(@timestamp, @name, @caplen, @length);"

/**
 * @brief Opens the sqlite meta db
 * 
 * @param db_path The sqlite db path
 * @return sqlite3* The sqlite structure pointer, or NULL on failure
 */
sqlite3* open_sqlite_meta_db(char *db_path);

/**
 * @brief Closes the sqlite db
 * 
 * @param ctx The sqlite db structure pointer
 */
void free_sqlite_meta_db(sqlite3 *db);

#endif
