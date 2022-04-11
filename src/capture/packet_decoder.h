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
 * @file packet_decoder.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the packet decoder utilities.
 */

#ifndef PACKET_DECODER_H
#define PACKET_DECODER_H

#include <pcap.h>

#include "../utils/utarray.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

#include "capture_config.h"

/**
 * @brief Extract packets from pcap packet data
 *
 * @param ltype The link type
 * @param header The packet header as per pcap
 * @param packet The packet data
 * @param interface The packet interface
 * @param hostname The packet hostname
 * @param id The packet id
 * @param tp_array The array of returned packet tuples
 * @return int Total count of packet tuples
 */
int extract_packets(char *ltype, const struct pcap_pkthdr *header, const uint8_t *packet,
                    char *interface, char *hostname, char *id, UT_array *tp_array);

#endif
