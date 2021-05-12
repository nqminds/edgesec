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
 * @file sqlite_pcap_writer.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the sqlite pcap writer utilities.
 */

#ifndef SQLITE_PCAP_WRITER_H
#define SQLITE_PCAP_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

#include "../utils/os.h"
#include "../utils/squeue.h"

#define PCAP_TABLE_NAME "pcap"
#define PCAP_CREATE_TABLE "CREATE TABLE " PCAP_TABLE_NAME " (id TEXT, timestamp INTEGER NOT NULL, name TEXT, interface TEXT, filter TEXT, caplen INTEGER, length INTEGER, " \
                         "PRIMARY KEY (id, timestamp, interface));"
#define PCAP_INSERT_INTO "INSERT INTO " PCAP_TABLE_NAME " VALUES(@id, @timestamp, @name, @interface, @filter, @caplen, @length);"

/**
 * @brief Opens the sqlite pcap db
 * 
 * @param db_path The sqlite db path
 * @param sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_pcap_db(char *db_path, sqlite3** sql);

/**
 * @brief Closes the sqlite db
 * 
 * @param ctx The sqlite db structure pointer
 */
void free_sqlite_pcap_db(sqlite3 *db);

/**
 * @brief Save a pcap entry into the sqlite db
 * 
 * @param db The sqlite db structure pointer
 * @param id The capturing id string
 * @param name The pcap file name
 * @param timestamp The timestamp value
 * @param caplen The capture len
 * @param length The offwire packet len
 * @param interface The interface string
 * @param filter The filter string
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_pcap_entry(sqlite3 *db, char *id, char *name, uint64_t timestamp,
                            uint32_t caplen, uint32_t length, char *interface, char *filter);
#endif
