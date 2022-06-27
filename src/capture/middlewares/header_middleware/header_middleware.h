/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the header middleware utilities.
 *
 */

#ifndef HEADER_MIDDLEWARE_H
#define HEADER_MIDDLEWARE_H

#include "../../middleware.h"

/**
 * @brief Packet Header Capture Middleware.
 * The header middleware stores packet headers and other packet metadata
 * into the capture SQLite database.
 * @author Alexandru Mereacre, Alois Klink
 */
extern struct capture_middleware header_middleware;
#endif
