/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the capture service.
 */

#ifndef CAPTURE_SERVICE_H
#define CAPTURE_SERVICE_H

#include <sqlite3.h>
#include <pcap.h>

#include "../utils/eloop.h"

#include "pcap_service.h"
#include "capture_config.h"

#define DB_BUSY_TIMEOUT 5000 // Sets the sqlite busy timeout in milliseconds

struct capture_middleware_context {
  struct capture_conf config;
  UT_array *handlers;
  char ifname[IFNAMSIZ];
};

/**
 * @brief Callback for pcap packet module
 *
 * @param ctx The capture context
 * @param pcap_ctx The pcap context
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
 * @brief Frees the capture context
 *
 * @param context The middleware context
 */
void free_capture_context(struct capture_middleware_context *context);

/**
 * @brief Runs the capture service thread
 *
 * @param ifname The capture interface name
 * @param config The capture service config structure
 * @param[out] id The returned thread id
 * @return int 0 on success, -1 on error
 */
int run_capture_thread(char *ifname, struct capture_conf const *config,
                       pthread_t *id);

#endif
