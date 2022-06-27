/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the dns packet decoder utilities.
 */

#ifndef DNS_DECODER_H
#define DNS_DECODER_H

#include "packet_decoder.h"

/**
 * @brief Decode dns packet
 *
 * @param cpac The captyure packet structure
 * @return true Success, false otherwise
 */
bool decode_dns_packet(struct capture_packet *cpac);
#endif
