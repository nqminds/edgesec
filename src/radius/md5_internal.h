/*
 * MD5 internal definitions
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * @file md5_internal.h
 * @author Jouni Malinen
 * @brief MD5 internal definitions.
 */

#ifndef MD5_INTERNAL_H
#define MD5_INTERNAL_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	uint8_t in[64];
};

int md5_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac);

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);

#endif /* MD5_INTERNAL_H */
