/**
 * @file
 * @author Alexandru Mereacre
 * @author Alois Klink
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of a generic middleware.
 */

#ifndef MIDDLEWARE_H
#define MIDDLEWARE_H

#include <stdint.h>
#include <sqlite3.h>

#include <eloop.h>
#include "./pcap_service.h"

// params is a pointer to an already allocated string
struct middleware_context {
  sqlite3 *db;
  struct eloop_data *eloop;
  struct pcap_context *pc;
  void *mdata;
  char *params;
};

/**
 * @brief Structure describing a middleware for the EDGESec capture service.
 *
 * All EDGESec capture service middlewares should expose a variable
 * of type ::capture_middleware only.
 *
 * You can then use the CMake function `edgesecAddCaptureMiddleware` to
 * add your middleware to the EDGESec capture service when building
 * EDGESec.
 * @authors Alois Klink, Alexandru Mereacre
 */
struct capture_middleware {
  /**
   * @brief Initialises the middleware
   *
   * @param db The sqlite3 db
   * @param db_path The sqlite3 db path
   * @param eloop The eloop structure
   * @param pc The pcap context
   * @param params The middleware params
   * @return The middleware context on success, NULL on failure
   */
  struct middleware_context *(*const init)(sqlite3 *db, char *db_path,
                                           struct eloop_data *eloop,
                                           struct pcap_context *pc,
                                           char *params);

  /**
   * @brief Runs the middleware.
   *
   * @param context The middleware context
   * @param ltype The packet type
   * @param header The pcap packet header
   * @param packet The pcap packet
   * @param ifname The capture interface
   * @retval 0 on success
   * @retval -1 on failure
   */
  int (*const process)(struct middleware_context *context, const char *ltype,
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
