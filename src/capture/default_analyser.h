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
 * @file default_analyser.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the default analyser service.
 */

#ifndef DEFAULT_ANALYSER_H
#define DEFAULT_ANALYSER_H

#include <sqlite3.h>
#include <pcap.h>

#include "../utils/eloop.h"
#include "capture_config.h"

#define MAX_DB_NAME_LENGTH MAX_RANDOM_UUID_LEN + STRLEN(SQLITE_EXTENSION)
#define MAX_PCAP_FILE_NAME_LENGTH MAX_RANDOM_UUID_LEN + STRLEN(PCAP_EXTENSION)

struct capture_context {
  struct eloop_data *eloop;
  uint32_t process_interval;
  struct packet_queue *pqueue;
  struct pcap_queue *cqueue;
  struct sqlite_header_context *header_db;
  sqlite3 *pcap_db;
  bool file_write;
  bool db_write;
  char db_name[MAX_DB_NAME_LENGTH];
  char *db_path;
  char pcap_path[MAX_OS_PATH_LEN];
  char *filter;
  char hostname[OS_HOST_NAME_MAX];
  ssize_t sync_store_size;
  ssize_t sync_send_size;
  char domain_command[MAX_SUPERVISOR_CMD_SIZE];
  char domain_delim;
  bool promiscuous;
  bool immediate;
  uint32_t buffer_timeout;
  char domain_server_path[MAX_OS_PATH_LEN];
  int domain_client;
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
 * @brief Starts the default analyser engine
 *
 * @param config The capture config structure
 * @return int 0 on success, -1 on failure
 */
int start_default_analyser(struct capture_conf *config);

#endif
