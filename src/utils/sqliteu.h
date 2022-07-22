/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the sqlite utilities.
 */

#ifndef SQLITEU_H
#define SQLITEU_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/**
 * @brief Executes and sqlite query statement
 *
 * @param db The sqlite db structure.
 * @param statement The sqlite query statement.
 * @return int 0 on success, -1 on failure.
 */
int execute_sqlite_query(sqlite3 *db, const char *statement);

/**
 * @brief Check if sqlite table exists
 *
 * @param db The sqlite db structure
 * @param table_name The table name
 * @return int 0 if it doesn't exist, 1 if it excists and -1 on failure
 */
int check_table_exists(sqlite3 *db, char *table_name);
#endif
