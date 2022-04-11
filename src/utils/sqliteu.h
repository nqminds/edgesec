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
 * @file sqliteu.h
 * @author Alexandru Mereacre
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
int execute_sqlite_query(sqlite3 *db, char *statement);

/**
 * @brief Check if sqlite table exists
 *
 * @param db The sqlite db structure
 * @param table_name The table name
 * @return int 0 if it doesn't exist, 1 if it excists and -1 on failure
 */
int check_table_exists(sqlite3 *db, char *table_name);
#endif
