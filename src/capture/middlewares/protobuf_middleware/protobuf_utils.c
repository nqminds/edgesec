/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the protobuf encoding utilities.
 */

#include <protobuf-c/protobuf-c.h>

// https://github.com/protobuf-c/protobuf-c/blob/master/protobuf-c/protobuf-c.c
size_t uint32_pack(uint32_t value, uint8_t *out) {
	unsigned rv = 0;

	if (value >= 0x80) {
		out[rv++] = value | 0x80;
		value >>= 7;
		if (value >= 0x80) {
			out[rv++] = value | 0x80;
			value >>= 7;
			if (value >= 0x80) {
				out[rv++] = value | 0x80;
				value >>= 7;
				if (value >= 0x80) {
					out[rv++] = value | 0x80;
					value >>= 7;
				}
			}
		}
	}
	/* assert: value<128 */
	out[rv++] = value;
	return rv;
}

// https://github.com/protobuf-c/protobuf-c/blob/master/protobuf-c/protobuf-c.c
size_t uint32_size(uint32_t v) {
	if (v < (1UL << 7)) {
		return 1;
	} else if (v < (1UL << 14)) {
		return 2;
	} else if (v < (1UL << 21)) {
		return 3;
	} else if (v < (1UL << 28)) {
		return 4;
	} else {
		return 5;
	}
}

size_t protobuf_c_message_del_get_packed_size(const ProtobufCMessage *message) {
  size_t message_size = protobuf_c_message_get_packed_size (message);
  uint32_t delimiter_size = uint32_size(message_size);

  return message_size + delimiter_size;
}

size_t protobuf_c_message_del_pack(const ProtobufCMessage *message, uint8_t *out) {
  size_t message_size = protobuf_c_message_get_packed_size (message);
  size_t delimiter_size = uint32_pack(message_size, out);

  return protobuf_c_message_pack(message, &out[delimiter_size]) +
         delimiter_size;
}