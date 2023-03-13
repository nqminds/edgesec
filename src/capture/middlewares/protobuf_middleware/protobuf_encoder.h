/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the protobuf encoder utilities.
 */

#ifndef PROTOBUF_ENCODER_H
#define PROTOBUF_ENCODER_H

#include "../header_middleware/packet_decoder.h"

/**
 * @brief Encodes the packet into a protobuf message
 *
 * @param[in] tp The packet
 * @param[out] buffer The encoded protobuf packet
 * @return the output buffer size, -1 on failure
 */
ssize_t encode_protobuf_packet(struct tuple_packet *tp, uint8_t **buffer);

/**
 * @brief Encodes the packet into a wrapper protobuf message
 *
 * @param[in] tp The packet
 * @param[out] buffer The encoded wrapper protobuf packet
 * @return the output buffer size, -1 on failure
 */
ssize_t encode_protobuf_sync_wrapper(struct tuple_packet *tp, uint8_t **buffer);
#endif
