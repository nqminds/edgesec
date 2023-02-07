/*
 * MD5 hash implementation and interface functions
 * Copyright (c) 2003-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * @file md5.h
 * @author Jouni Malinen
 * @brief MD5 hash implementation and interface functions.
 */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#define MD5_MAC_LEN 16

#define hmac_md5(key, key_len, data, data_len, mac)                            \
  edge_hmac_md5((key), (key_len), (data), (data_len), (mac))

/**
 * HMAC-MD5 over data buffer (RFC 2104)
 *
 * @param key Key for HMAC operations
 * @param key_len Length of the key in bytes
 * @param data Pointers to the data area
 * @param data_len Length of the data area
 * @param[out] mac Buffer for the hash (16 bytes)
 * @retval  0 on success
 * @retval -1 on failure
 */
int edge_hmac_md5(const uint8_t *key, size_t key_len, const uint8_t *data,
                  size_t data_len, uint8_t *mac);

#endif /* MD5_H */
