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

struct capture_middleware_context {
  struct capture_conf config;
  UT_array *handlers;
  char ifname[IFNAMSIZ];
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
 * @param context The middleware context
 * @return int 0 on success, -1 on failure
 */
int run_capture(struct capture_middleware_context *context);

/**
 * @brief Runs the capture service thread
 *
 * @param ifname The capture interface name
 * @param config The capture service config structure
 * @param id The returned thread id
 * @return int 0 on success, -1 on error
 */
int run_capture_thread(char *ifname, struct capture_conf const *config,
                       pthread_t *id);

#endif
