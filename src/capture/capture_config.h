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
 * @file capture_config.h
 * @author Alexandru Mereacre
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
};

#endif
