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
 * @file pcap_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the pcap service utilities.
 */

#ifndef PCAP_SERVICE_H
#define PCAP_SERVICE_H

#include <sys/types.h>
#include <stdbool.h>

typedef void (*capture_callback_fn)(struct pcap_pkthdr *header, uint8_t *packet, const void *ctx);

/**
 * @brief Pcap context structure definition
 * 
 */
struct pcap_context {
  int pcap_fd;                  /**< The pcap selectable fd */
  pcap_t *pd;                   /**< The pcap structure */
  capture_callback_fn pcap_fn;  /**< The pcap capture callback */
  void *fn_ctx;              /**< The context for callback function */
};

/**
 * @brief Executes the libpcap service
 * 
 * @param interface The capture interface
 * @param immediate The immediate mode flag
 * @param promiscuous The promiscuous mode flag
 * @param timeout The timeout (in milliseconds)
 * @param filter The capture filter string
 * @param pcap_fn The pcap capture callback
 * @param fn_ctx The context for callback function
 * @param pctx The returned pcap context
 * @return 0 on success, -1 on failure
 */
int run_pcap(char *interface, bool immediate, bool promiscuous,
             int timeout, char *filter, capture_callback_fn pcap_fn,
             void *fn_ctx, struct pcap_context** pctx);

/**
 * @brief Captures a pcap packet
 * 
 * @param ctx The pcap context structure
 * @return int 0 on success, -1 otherwise
 */
int capture_pcap(struct pcap_context *ctx);

/**
 * @brief Saves a packet packet into file
 * 
 * @param ctx The pcap context
 * @param file_path The file path to save the packet
 * @param header The packet header
 * @param packet The packet data
 * @return int 0 on success, -1 on failure
 */
int dump_file_pcap(struct pcap_context *ctx, char *file_path, struct pcap_pkthdr *header, uint8_t *packet);

/**
 * @brief Closes the pcap service
 * 
 * @param ctx The pcap context
 */
void close_pcap(struct pcap_context *ctx);
#endif
