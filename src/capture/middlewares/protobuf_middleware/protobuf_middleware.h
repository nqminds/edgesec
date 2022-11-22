/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the protobuf middleware utilities.
 */

#ifndef PROTOBUF_MIDDLEWARE_H
#define PROTOBUF_MIDDLEWARE_H

#include "../../middleware.h"

/**
 * @brief pipe the serialised protobuf tuple packets
 *
 * @param path[in] The pipe file path
 * @param fd[in] The pipe file descriptor
 * @param p[in] The tuple packet
 * @return 0 on success, -1 otherwise
 */
int pipe_protobuf_tuple_packet(const char *path, int *fd,
                               struct tuple_packet *p);

/**
 * @brief pipe the serialised protobuf packets
 *
 * @param path[in] The pipe file path
 * @param fd[in] The pipe file descriptor
 * @param packets[in] The array of packets
 * @return 0 on success, -1 otherwise
 */
int pipe_protobuf_packets(const char *path, int *fd, UT_array *packets);

/**
 * @brief protobuf Capture Middleware.
 * The protobuf capture middleware generates protobuf
 * messages from caprtured traffic.
 * @authors Alexandru Mereacre
 */
extern struct capture_middleware protobuf_middleware;
#endif
