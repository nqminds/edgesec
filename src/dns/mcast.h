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
 * @file mcast.h
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
int join_mcast(int fd, const struct sockaddr_storage *sa, socklen_t sa_len, uint32_t ifindex);

/**
 * @brief Create a receive multicast socket
 * 
 * @param sa The socket address
 * @param sa_len The socket address length
 * @param ifindex The interface index
 * @return 0 on success, -1 on failuer
 */
int create_recv_mcast(const struct sockaddr_storage *sa, socklen_t sa_len, uint32_t ifindex);

/**
 * @brief Create a send multicast socket
 * 
 * @param sa The socket address
 * @param sa_len The socket address length
 * @param ifindex The interface index
 * @return 0 on success, -1 on failuer
 */
int create_send_mcast(const struct sockaddr_storage *sa, socklen_t sa_len, uint32_t ifindex);

#endif //MCAST_H
