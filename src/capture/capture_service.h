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
 * @file capture_service.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the capture service.
 */

#ifndef CAPTURE_SERVICE_H
#define CAPTURE_SERVICE_H

#include <sqlite3.h>
#include <pcap.h>

#include "../utils/eloop.h"

#include "pcap_service.h"
#include "capture_config.h"

typedef struct middleware_context *(*init_middleware)(sqlite3 *db,
                                                      char *db_path,
                                                      struct eloop_data *eloop,
                                                      struct pcap_context *pc);

typedef int (*process_middleware)(struct middleware_context *context,
                                  char *ltype, struct pcap_pkthdr *header,
                                  uint8_t *packet, char *ifname);

typedef void (*free_middleware)(struct middleware_context *context);

struct middleware_handlers {
  init_middleware init;
  process_middleware process;
  free_middleware freem;
};

struct middleware_context {
  sqlite3 *db;
  struct eloop_data *eloop;
  struct pcap_context *pc;
  void *mdata;
};

/**
 * @brief Callback for pcap packet module
 *
 * @param ctx The capture context
 * @param ctx The pcap context
 * @param ltype The link type
 * @param header pcap header structure
 * @param packet Returned pcap packet
 */
void pcap_callback(const void *ctx, const void *pcap_ctx, char *ltype,
                   struct pcap_pkthdr *header, uint8_t *packet);

/**
 * @brief Return the pcap folder path
 *
 * @param capture_db_path The capture db path
 * @param pcap_path The returned pcap folder path
 * @return int 0 on success, -1 on failure
 */
int get_pcap_folder_path(char *capture_db_path, char *pcap_path);

/**
 * @brief Runs the capture service
 *
 * @param ifname The interface to capture
 * @param config The capture config structure
 * @return int 0 on success, -1 on failure
 */
int run_capture(char *ifname, struct capture_conf *config);

/**
 * @brief Runs the capture service thread
 *
 * @param ifname The capture interface name
 * @param config The capture service config structure
 * @param id The returned thread id
 * @return int 0 on success, -1 on error
 */
int run_capture_thread(char *ifname, struct capture_conf *config,
                       pthread_t *id);

#endif
