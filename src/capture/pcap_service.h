/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the pcap service utilities.
 */

#ifndef PCAP_SERVICE_H
#define PCAP_SERVICE_H

#include <linux/if.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>

#include "../utils/utarray.h"

typedef void (*capture_callback_fn)(const void *ctx, const void *pcap_ctx,
                                    char *ltype, struct pcap_pkthdr *header,
                                    uint8_t *packet);

/**
 * @brief Pcap context structure definition
 *
 */
struct pcap_context {
  int pcap_fd;                 /**< The pcap selectable fd */
  pcap_t *pd;                  /**< The pcap structure */
  char ifname[IFNAMSIZ];       /**< The pcap interface */
  capture_callback_fn pcap_fn; /**< The pcap capture callback */
  void *fn_ctx;                /**< The context for callback function */
};

/**
 * @brief Starts the blocking pcap loop
 *
 * @param ctx The pcap context
 * @return int 0 on success, -1 on error, -2 if the loop terminated
 */
int capture_pcap_start(struct pcap_context *ctx);

/**
 * @brief Stops the blocking pcap loop
 *
 * @param ctx The pcap context
 */
void capture_pcap_stop(struct pcap_context *ctx);

/**
 * @brief Get the pcap config datalink value
 *
 * @param ctx The pcap context
 * @return int the config value
 */
int get_pcap_datalink(struct pcap_context *ctx);

/**
 * @brief Executes the libpcap service
 *
 * @param interface The capture interface
 * @param immediate The immediate mode flag
 * @param promiscuous The promiscuous mode flag
 * @param timeout The timeout (in milliseconds)
 * @param filter The capture filter string
 * @param nonblock  Sets the capture to nonblocking mode
 * @param pcap_fn The pcap capture callback
 * @param fn_ctx The context for callback function
 * @param pctx The returned pcap context
 * @return 0 on success, -1 on failure
 */
int run_pcap(char *interface, bool immediate, bool promiscuous, int timeout,
             char *filter, bool nonblock, capture_callback_fn pcap_fn,
             void *fn_ctx, struct pcap_context **pctx);

/**
 * @brief Captures a pcap packet
 *
 * @param ctx The pcap context structure
 * @return int 0 on success, -1 otherwise
 */
int capture_pcap_packet(struct pcap_context *ctx);

/**
 * @brief Saves a packet packet into file
 *
 * @param ctx The pcap context
 * @param file_path The file path to save the packet
 * @param header The packet header
 * @param packet The packet data
 * @return int 0 on success, -1 on failure
 */
int dump_file_pcap(struct pcap_context *ctx, char *file_path,
                   struct pcap_pkthdr *header, uint8_t *packet);

/**
 * @brief Closes the pcap service
 *
 * @param ctx The pcap context
 */
void close_pcap(struct pcap_context *ctx);

/**
 * @brief Frees a pcap list
 *
 * @param ctx_list The pcap list
 */
void free_pcap_list(UT_array *ctx_list);

/**
 * @brief Creates a pcap list
 *
 * @return UT_array* The pcap list, NULL on failure
 */
UT_array *create_pcap_list(void);
#endif
