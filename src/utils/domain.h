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

#include <sys/un.h>
#include <sys/types.h>

#define DOMAIN_SOCKET_NAME_SIZE 14

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Client address structure definition
 *
 */
struct client_address {
  struct sockaddr_un addr;
  int len;
};

/**
 * @brief Create a domain client object
 *
 * @param addr The socket addr, if NULL is auto genereated and hidden
 * @return int Client socket
 */
int create_domain_client(char *add);

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
 * @param claddr The sender address structure
 * @param flags The flags for recvfrom function
 * @return ssize_t Size of read data
 */
ssize_t read_domain_data(int sock, char *data, size_t data_len,
                         struct client_address *addr, int flags);

/**
 * @brief Read data from the domain server socket with a string address
 *
 * @param sock Domain Server socket
 * @param data Data buffer
 * @param data_len Data buffer length
 * @param addr Sender address
 * @param flags The flags for recvfrom function
 * @return ssize_t Size of read data
 */
ssize_t read_domain_data_s(int sock, char *data, size_t data_len, char *addr,
                           int flags);

/**
 * @brief Write data to the domain server socket
 *
 * @param sock Domain server socket
 * @param data Data buffer
 * @param data_len Data buffer length
 * @param addr The recipient address structure
 * @return ssize_t Size of written data
 */
ssize_t write_domain_data(int sock, char *data, size_t data_len,
                          struct client_address *addr);

/**
 * @brief Write data to the domain server socket with a string address
 *
 * @param sock Domain server socket
 * @param data Data buffer
 * @param data_len Data buffer length
 * @param addr Client address (string)
 * @return ssize_t Size of written data
 */
ssize_t write_domain_data_s(int sock, char *data, size_t data_len, char *addr);

/**
 * @brief Closes the domain socket
 *
 * @param sfd The domain socket
 * @return int 0 on success, -1 on failure
 */
int close_domain(int sfd);

/**
 * @brief Write and read a domain data string
 *
 * @param socket_path The domain socket path
 * @param write_str The write string
 * @param reply The reply string
 * @return int 0 on success, -1 on failure
 */
int writeread_domain_data_str(char *socket_path, char *write_str, char **reply);
#ifdef __cplusplus
}
#endif

#endif
