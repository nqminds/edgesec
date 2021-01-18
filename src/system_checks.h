/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file system_checks.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the systems commands checks.
 */

#ifndef SYSTEM_CHECKS_H
#define SYSTEM_CHECKS_H

#include <inttypes.h>
#include <stdbool.h>

#include "utils/utarray.h"
#include "utils/hashmap.h"

/**
 * @brief Check if the system binaries are present and return their absolute paths
 * 
 * @param commands Array of system binaries name strings
 * @param bin_path_arr Array of system binaries default fodler paths
 * @param hmap_bin_hashes Map of systems binaries to hashes
 * @return hmap_str_keychar* Map for binary to path 
 */
hmap_str_keychar *check_systems_commands(char *commands[], UT_array *bin_path_arr, hmap_str_keychar *hmap_bin_hashes);

#endif