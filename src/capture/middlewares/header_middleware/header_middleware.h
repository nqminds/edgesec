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
 * @file header_middleware.h
 * @author Alexandru Mereacre
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
