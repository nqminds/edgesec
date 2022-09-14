/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the capture config structures.
 *
 * Defines the function to generate the config parameters for the capture
 * service. It also defines all the metadata and database schema for the
 * captured packets.
 */

#ifndef CAPTURE_CONFIG_H
#define CAPTURE_CONFIG_H

#include <stdbool.h>

#include "../utils/os.h"

#define MAX_FILTER_SIZE                                                        \
  4094 /* Maximum length of the filter string for libpcap */

#define MAX_MIDDLEWARE_PARAMS_SIZE                                             \
  4094 /* Maximum length of the middleware params string */

/**
 * @brief The capture configuration structure
 *
 */
struct capture_conf {
  bool promiscuous; /**< Specifies whether the interface is to be put into
                       promiscuous mode. If promiscuous param is non-zero,
                       promiscuous mode will be set, otherwise it will not be
                       set */
  bool immediate;   /**< Sets whether immediate mode should be set on a capture
                       handle when the handle is activated. If immediate param is
                       non-zero, immediate mode will be set, otherwise it will not
                       be set. */
  uint32_t
      buffer_timeout; /**< Specifies the packet buffer timeout, as a
                         non-negative value, in milliseconds. (See pcap(3PCAP)
                         for an explanation of the packet buffer timeout.) */
  char capture_db_path[MAX_OS_PATH_LEN]; /**< Specifies the path to the sqlite3
                                            dbs */
  char filter[MAX_FILTER_SIZE]; /**< Specifies the filter expression or pcap lib
                                 */
  char middleware_params[MAX_MIDDLEWARE_PARAMS_SIZE]; /**< Specifies the
                                                         middleware params
                                                         string*/
};

#endif
