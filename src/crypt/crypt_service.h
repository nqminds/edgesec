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
 * @file crypt_service.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of crypt service configuration utilities.
 */
#ifndef CRYPT_SERVICE_H
#define CRYPT_SERVICE_H

#include <sqlite3.h>

#include "crypt_config.h"

#include "../utils/os.h"
#include "../utils/utarray.h"

/**
 * @brief Load the crypt service
 * 
 * @param crypt_db_path The crypt db path
 * @return struct crypt_context* The crypt contex, NULL on failure
 */
struct crypt_context* load_crypt_service(char *crypt_db_path);

/**
 * @brief Frees the crypt context
 * 
 * @param ctx The crypt context
 */
void free_crypt_service(struct crypt_context *ctx);

#endif