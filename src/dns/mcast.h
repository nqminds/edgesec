/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the definition of mDNS utils.
 */

#ifndef MCAST_H
#define MCAST_H

#include <stdint.h>
#include <sys/socket.h>

/**
 * @brief Join a multicast socket
 *
 * @param fd The socket descriptor
 * @param sa The socket address
 * @param sa_len The socket address length
 * @param ifindex The interface index
 * @return 0 on success, -1 on failuer
 */
int join_mcast(int fd, const struct sockaddr_storage *sa, socklen_t sa_len,
               uint32_t ifindex);

/**
 * @brief Create a receive multicast socket
 *
 * @param sa The socket address
 * @param sa_len The socket address length
 * @param ifindex The interface index
 * @return 0 on success, -1 on failuer
 */
int create_recv_mcast(const struct sockaddr_storage *sa, socklen_t sa_len,
                      uint32_t ifindex);

/**
 * @brief Create a send multicast socket
 *
 * @param sa The socket address
 * @param sa_len The socket address length
 * @param ifindex The interface index
 * @return 0 on success, -1 on failuer
 */
int create_send_mcast(const struct sockaddr_storage *sa, socklen_t sa_len,
                      uint32_t ifindex);

#endif // MCAST_H
