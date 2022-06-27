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
 * @file pcap_middleware.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the pcap middleware utilities.
 */

#ifndef PCAP_MIDDLEWARE_H
#define PCAP_MIDDLEWARE_H

#include "../../middleware.h"

/**
 * @brief PCAP Capture Middleware.
 * The PCAP capture middleware stores the full PCAP data from captured
 * middlewares. Because this is a lot of data, we recommended using the
 * ::cleaner_middleware too, to automatically cleanup/delete old PCAP files.
 * @author Alexandru Mereacre, Alois Klink
 */
extern struct capture_middleware pcap_middleware;
#endif
