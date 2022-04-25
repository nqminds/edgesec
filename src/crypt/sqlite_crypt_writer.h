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

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/squeue.h"

#define CRYPT_STORE_TABLE_NAME "store"
#define CRYPT_STORE_CREATE_TABLE                                               \
  "CREATE TABLE " CRYPT_STORE_TABLE_NAME                                       \
  " (key TEXT NOT NULL, value TEXT, id TEXT, iv TEXT, "                        \
  "PRIMARY KEY (key));"
#define CRYPT_STORE_INSERT_INTO                                                \
  "INSERT INTO " CRYPT_STORE_TABLE_NAME " VALUES(@key, @value, @id, @iv);"
#define CRYPT_STORE_DELETE_FROM                                                \
  "DELETE FROM " CRYPT_STORE_TABLE_NAME " WHERE key=@key;"
#define CRYPT_STORE_GET                                                        \
  "SELECT value, id, iv FROM  " CRYPT_STORE_TABLE_NAME " WHERE key=?;"

#define CRYPT_SECRETS_TABLE_NAME "secrets"
#define CRYPT_SECRETS_CREATE_TABLE                                             \
  "CREATE TABLE " CRYPT_SECRETS_TABLE_NAME                                     \
  " (id TEXT NOT NULL, value TEXT, salt TEXT, iv TEXT, "                       \
  "PRIMARY KEY (id));"
#define CRYPT_SECRETS_INSERT_INTO                                              \
  "INSERT INTO " CRYPT_SECRETS_TABLE_NAME " VALUES(@id, @value, @salt, @iv);"
#define CRYPT_SECRETS_GET                                                      \
  "SELECT value, salt, iv FROM  " CRYPT_SECRETS_TABLE_NAME " WHERE id=?;"

/**
 * @brief The store row structure definition
 *
 */
struct store_row {
  char *key;   /**< The key */
  char *value; /**< The stored value */
  char *id;    /**< The key ID */
  char *iv;    /**< The IV of the key */
};

/**
 * @brief The secrets row structure definition
 *
 */
struct secrets_row {
  char *id;    /**< The key ID */
  char *value; /**< The key value */
  char *salt;  /**< The key salt */
  char *iv;    /**< The IV of the key */
};

/**
 * @brief Opens the sqlite crypt db
 *
 * @param db_path The sqlite db path
 * @param sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_crypt_db(char *db_path, sqlite3 **sql);

/**
 * @brief Closes the sqlite db
 *
 * @param ctx The sqlite db structure pointer
 */
void free_sqlite_crypt_db(sqlite3 *db);

/**
 * @brief Save a store entry into the sqlite db
 *
 * @param db The sqlite db structure pointer
 * @param row The store row structure
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_store_entry(sqlite3 *db, struct store_row *row);

/**
 * @brief Save a secrets entry into the sqlite db
 *
 * @param db The sqlite db structure pointer
 * @param row The secrets row structure
 * @return int 0 on success, -1 on failure
 */
int save_sqlite_secrets_entry(sqlite3 *db, struct secrets_row *row);

/**
 * @brief Get the sqlite store entry object
 *
 * @param db The sqlite db structure pointer
 * @param key The store column key
 * @return struct store_row* row value, NULL on failure
 */
struct store_row *get_sqlite_store_row(sqlite3 *db, char *key);

/**
 * @brief Frees a store row entry
 *
 * @param column The store row value
 */
void free_sqlite_store_row(struct store_row *row);

/**
 * @brief Get the sqlite secrets entry object
 *
 * @param db The sqlite db structure pointer
 * @param id The secrets column id
 * @return struct secrets_row* row value, NULL on failure
 */
struct secrets_row *get_sqlite_secrets_row(sqlite3 *db, char *id);

/**
 * @brief Frees a secrets row entry
 *
 * @param column The secrets row value
 */
void free_sqlite_secrets_row(struct secrets_row *row);
#endif
