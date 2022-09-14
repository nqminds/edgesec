/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the socket control utilities.
 */

#ifndef SOCKCTL_H
#define SOCKCTL_H

#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>

enum SOCKET_TYPE {
  SOCKET_TYPE_NONE = 0,
  SOCKET_TYPE_DOMAIN,
  SOCKET_TYPE_UDP,
};

/**
 * @brief Client address structure definition
 *
 */
struct client_address {
  union {
    struct sockaddr_un addr_un;
    struct sockaddr_in addr_in;
  } caddr;
  int len;
  enum SOCKET_TYPE type;
};

/**
 * @brief Create a domain client object
 *
 * @param addr The socket addr, if NULL is auto genereated and hidden
 * @return int Client socket
 */
int create_domain_client(char *addr);

/**
 * @brief Create a domain server object
 *
 * @param server_path Server UNIX domain socket path
 * @return int Domain server socket
 */
int create_domain_server(char *server_path);

/**
 * @brief Create a udp server object
 *
 * @param port Server port
 * @return int UDP server socket
 */
int create_udp_server(unsigned int port);

/**
 * @brief Read data from the server socket
 *
 * @param sock Server socket
 * @param data Data buffer
 * @param data_len Data buffer length
 * @param addr The sender address structure
 * @param flags The flags for recvfrom function
 * @return ssize_t Size of read data
 */
ssize_t read_socket_data(int sock, char *data, size_t data_len,
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
 * @brief Write data to the erver socket
 *
 * @param sock Server socket
 * @param data Data buffer
 * @param data_len Data buffer length
 * @param addr The recipient address structure
 * @return ssize_t Size of written data
 */
ssize_t write_socket_data(int sock, const char *data, size_t data_len,
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
ssize_t write_domain_data_s(int sock, const char *data, size_t data_len,
                            char *addr);

/**
 * @brief Write and read a domain data string
 *
 * @param socket_path The domain socket path
 * @param write_str The write string
 * @param reply The reply string
 * @return int 0 on success, -1 on failure
 */
int writeread_domain_data_str(char *socket_path, const char *write_str,
                              char **reply);
#endif
