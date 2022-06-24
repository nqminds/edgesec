/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file middleware.h
 * @author Alois Klink
 * @brief File containing the definition of a generic middleware.
 */

#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include <sqlite3.h>
#include <stdint.h>

#include "./pcap_service.h"
#include "../utils/eloop.h"

struct middleware_context {
  sqlite3 *db;
  struct eloop_data *eloop;
  struct pcap_context *pc;
  void *mdata;
};

/**
 * @brief Structure describing a middleware for the EDGESec capture service
 * @author Alois Klink, Alexandru Mereacre
 * All EDGESec capture service middlewares should expose the following
 * structure only.
 */
struct capture_middleware {
  /**
   * @brief Initialises the middleware
   *
   * @param db The sqlite3 db
   * @param db_path The sqlite3 db path
   * @param eloop The eloop structure
   * @param pc The pcap context
   * @return The middleware context on success, NULL on failure
   */
  struct middleware_context *(*const init)(sqlite3 *db, char *db_path,
                                           struct eloop_data *eloop,
                                           struct pcap_context *pc);

  /**
   * @brief Runs the middleware.
   *
   * @param context The middleware context
   * @param ltype The packet type
   * @param header The pcap packet header
   * @param packet The pcap packet
   * @param ifname The capture interface
   * @return int 0 on success, -1 on failure
   */
  int (*const process)(struct middleware_context *context, char *ltype,
                       struct pcap_pkthdr *header, uint8_t *packet,
                       char *ifname);

  /**
   * @brief Frees the middleware context
   *
   * @param context The middleware context
   */
  void (*const free)(struct middleware_context *context);

  /**
   * @brief Human readable name for middleware.
   *
   * Human readable name for this middleware. Currently only used for logs.
   */
  const char *const name;
};
#endif
