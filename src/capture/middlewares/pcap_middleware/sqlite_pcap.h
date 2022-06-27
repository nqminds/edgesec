/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file sqlite_pcap.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the sqlite pcap utilities.
 */

#ifndef SQLITE_PCAP_H
#define SQLITE_PCAP_H

#include <stdint.h>
#include <sqlite3.h>

#include "../../../utils/allocs.h"
#include "../../../utils/os.h"
#include "../../../utils/squeue.h"

#define PCAP_TABLE_NAME "pcap"
#define PCAP_CREATE_TABLE                                                      \
  "CREATE TABLE " PCAP_TABLE_NAME                                              \
  " (timestamp INTEGER NOT NULL, name TEXT NOT NULL, "                         \
  "caplen INTEGER, length INTEGER, "                                           \
  "PRIMARY KEY (name));"
#define PCAP_INSERT_INTO                                                       \
  "INSERT INTO " PCAP_TABLE_NAME " VALUES(@timestamp, @name, @caplen, "        \
  "@length);"
#define PCAP_SELECT_FIRST_ENTRY                                                \
  "SELECT timestamp,caplen FROM " PCAP_TABLE_NAME                              \
  " ORDER BY timestamp ASC LIMIT 1;"
#define PCAP_SUM_GROUP                                                         \
  "SELECT timestamp,caplen FROM " PCAP_TABLE_NAME                              \
  " WHERE timestamp > @lt ORDER BY timestamp ASC LIMIT @lim;"
#define PCAP_SELECT_GROUP                                                      \
  "SELECT timestamp,name FROM " PCAP_TABLE_NAME                                \
  " WHERE timestamp >= @lt ORDER BY timestamp ASC LIMIT @lim;"
#define PCAP_DELETE_GROUP                                                      \
  "DELETE FROM " PCAP_TABLE_NAME " WHERE timestamp >= @lt AND timestamp <= "   \
  "@ht;"

struct pcap_file_meta {
  uint64_t timestamp;
  char *name;
};

/**
 * @brief Initialisez the sqlite pcap db tables
 *
 * @param db The sqlite3 db
 * @return 0 on success, -1 on failure
 */
int init_sqlite_pcap_db(sqlite3 *db);

/**
 * @brief Save a pcap entry into the sqlite db
 *
 * @param db The sqlite db structure pointer
 * @param name The pcap file name
 * @param timestamp The timestamp value
 * @param caplen The capture len
 * @param length The offwire packet len
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_pcap_entry(sqlite3 *db, char *name, uint64_t timestamp,
                           uint32_t caplen, uint32_t length);

/**
 * @brief Returns the first pcap entry timestamp
 *
 * @param db The sqlite db structure pointer
 * @param timestamp The returned timestamp value
 * @param caplen The returned caplen value
 * @return int 0 on success, 1 for no data and -1 on failure
 */
int get_first_pcap_entry(sqlite3 *db, uint64_t *timestamp, uint64_t *caplen);

/**
 * @brief Returns the pcap meta array
 *
 * @param db The sqlite db structure pointer
 * @param lt The lower timestamp
 * @param lim The limit number of rows
 * @param pcap_meta_arr The pcap meta array
 * @return int 0 on success, 1 for no data and -1 on failure
 */
int get_pcap_meta_array(sqlite3 *db, uint64_t lt, uint32_t lim,
                        UT_array *pcap_meta_arr);

/**
 * @brief Removes a set of entries
 *
 * @param db The sqlite db structure pointer
 * @param lt The lower timestamp
 * @param ht The higher timestamp
 * @return int 0 on success, 1 for no data and -1 on failure
 */
int delete_pcap_entries(sqlite3 *db, uint64_t lt, uint64_t ht);

/**
 * @brief Calculates the sum of the group of a pcap
 *
 * @param db The sqlite db structure pointer
 * @param lt The lower bound timestamp
 * @param lim The limit number of rows
 * @param ht The returned upper timestamp
 * @param sum The returned sum
 * @return int 0 on success, 1 for no data and -1 on failure
 */
int sum_pcap_group(sqlite3 *db, uint64_t lt, uint32_t lim, uint64_t *ht,
                   uint64_t *sum);

#endif
