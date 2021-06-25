/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file domain.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the domain utilities.
 */

#ifndef DOMAIN_H
#define DOMAIN_H

#include <sys/types.h>

#define MAX_DOMAIN_RECEIVE_DATA 1024
#define DOMAIN_SOCKET_NAME_SIZE 14

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a domain client object
 * 
 * @param socket_name The returned client address
 * @return int Client socket
 */
int create_domain_client(char *socket_name);

/**
 * @brief Create a domain server object
 * 
 * @param server_path Server UNIX domain socket path
 * @return int Domain server socket
 */
int create_domain_server(char *server_path);

/**
 * @brief Read data from the domain server socket
 * 
 * @param sock Domain Server socket
 * @param data Data buffer
 * @param data_len Data buffer length
 * @param addr Sender address
 * @param flags The flags for recvfrom function
 * @return ssize_t Size of read data
 */
ssize_t read_domain_data(int sock, char *data, size_t data_len, char *addr, int flags);

/**
 * @brief Write data to the domain server socket
 * 
 * @param sock Domain server socket
 * @param data Data buffer
 * @param data_len Data buffer length
 * @param addr Client address
 * @return ssize_t Size of written data
 */
ssize_t write_domain_data(int sock, char *data, size_t data_len, char *addr);

/**
 * @brief Closes teh domain socket
 * 
 * @param sfd The domain socket
 * @return int 0 on success, -1 on failure
 */
int close_domain(int sfd);
#ifdef __cplusplus
}
#endif

#endif