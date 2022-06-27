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
 * @file cleaner_middleware.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the middleware cleaner utilities.
 */

#ifndef CLEANER_MIDDLEWARE_H
#define CLEANER_MIDDLEWARE_H

#include "../../middleware.h"

/**
 * @brief Cleaner Middleware.
 * The cleaner middleware is designed to periodically remove the oldest
 * PCAP files when the use more than `CLEANER_STORE_SIZE` KiB.
 * @author Alexandru Mereacre, Alois Klink
 */
extern struct capture_middleware cleaner_middleware;
#endif
