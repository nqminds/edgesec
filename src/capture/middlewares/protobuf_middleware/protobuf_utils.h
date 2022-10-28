/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the protobuf encoding utilities.
 */

#ifndef PROTOBUF_UTILS_H
#define PROTOBUF_UTILS_H

#include <protobuf-c/protobuf-c.h>


/**
 * @brief Determine the number of bytes required to store the
 * length delimited serialised message.
 *
 * @param message[in] The message object to serialise.
 * @return number of bytes
 */
size_t protobuf_c_message_del_get_packed_size(const ProtobufCMessage *message);

/**
 * @brief Serialise a message from its in-memory representation
 * adding the lenght delimiter
 *
 * @param message[in] The message object to serialise.
 * @param buffer[out] Buffer to store the bytes of the serialised message
 * @return the output buffer size
 */
size_t protobuf_c_message_del_pack(const ProtobufCMessage *message, uint8_t *out);

#endif