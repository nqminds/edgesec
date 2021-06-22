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
 * @file domain.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the domain utils.
 */

#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>

#include "os.h"
#include "log.h"

void init_domain_addr(struct sockaddr_un *unaddr, char *addr)
{
  os_memset(unaddr, 0, sizeof(struct sockaddr_un));
  unaddr->sun_family = AF_UNIX;
  os_strlcpy(unaddr->sun_path, addr, sizeof(unaddr->sun_path));
}

char* generate_socket_name(char *buf)
{
  unsigned char crypto_rand[4];
  if (os_get_random(crypto_rand, 4) == -1) {
    log_trace("os_get_random fail");
    return NULL;
  }
  sprintf(buf, "%x%x%x%x.sock", crypto_rand[0], crypto_rand[1], crypto_rand[2], crypto_rand[3]);
  return buf;
}

int create_domain_client(char *socket_name)
{
  struct sockaddr_un claddr;
  int sock;

  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    log_err("socket");
    return -1;
  }

  if (generate_socket_name(socket_name) == NULL) {
    log_trace("generate_random_name fail");
    return -1;
  }

  init_domain_addr(&claddr, socket_name);

  if (bind(sock, (struct sockaddr *) &claddr, sizeof(struct sockaddr_un)) == -1) {
    log_err("bind");
    return -1;
  }

  return sock;
}

int create_domain_server(char *server_path)
{
  struct sockaddr_un svaddr;
  int sfd;

  sfd = socket(AF_UNIX, SOCK_DGRAM, 0);       /* Create server socket */
  if (sfd == -1) {
    log_err("socket");
    return -1;
  }

  /* Construct well-known address and bind server socket to it */

  /* For an explanation of the following check, see the erratum note for
     page 1168 at http://www.man7.org/tlpi/errata/.
  */
  if (strlen(server_path) > sizeof(svaddr.sun_path) - 1) {
    log_trace("Server socket path too long: %s", server_path);
    return -1;
  }

  if (remove(server_path) == -1 && errno != ENOENT) {
    log_err("remove-%s", server_path);
    return -1;
  }

  init_domain_addr(&svaddr, server_path);

  if (bind(sfd, (struct sockaddr *) &svaddr, sizeof(struct sockaddr_un)) == -1) {
    log_err("bind");
    return -1;
  }

  return sfd;
}

ssize_t read_domain_data(int sock, char *data, size_t data_len, char *addr)
{
  struct sockaddr_un unaddr;
  int addr_len = sizeof(struct sockaddr_un);

  if (data == NULL) {
    log_trace("error get_domain_data data param=NULL");
    return -1;
  }

  ssize_t num_bytes = recvfrom(sock, data, data_len, 0, (struct sockaddr *) &unaddr, &addr_len);
  if (num_bytes == -1) {
    log_err("recvfrom");
    return -1;
  }

  if (addr != NULL)
    strcpy(addr, unaddr.sun_path);

  return num_bytes;
}

ssize_t write_domain_data(int sock, char *data, size_t data_len, char *addr)
{
  struct sockaddr_un unaddr;
  int addr_len = sizeof(struct sockaddr_un);

  if (data == NULL) {
    log_trace("error write_domain_data data param=NULL");
    return -1;
  }

  if (addr == NULL) {
    log_trace("error write_domain_data addr param=NULL");
    return -1;
  }

  init_domain_addr(&unaddr, addr);

  ssize_t num_bytes = sendto(sock, data, data_len, 0, (struct sockaddr *) &unaddr, addr_len);
  if (num_bytes == -1) {
    log_err("sendto");
    return -1;
  }

  return num_bytes;
}

int close_domain(int sfd)
{
  if (sfd) {
    return close(sfd);
  }

  return 0;
}