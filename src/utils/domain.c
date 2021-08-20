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

#include "domain.h"

#include "os.h"
#include "log.h"

#define SOCK_EXTENSION ".sock"
void init_domain_addr(struct sockaddr_un *unaddr, char *addr)
{
  os_memset(unaddr, 0, sizeof(struct sockaddr_un));
  unaddr->sun_family = AF_UNIX;
  os_strlcpy(unaddr->sun_path, addr, sizeof(unaddr->sun_path));
}

char* generate_socket_name(void)
{
  unsigned char crypto_rand[4];
  char *buf = NULL;
  if (os_get_random(crypto_rand, 4) == -1) {
    log_trace("os_get_random fail");
    return NULL;
  }
  buf = os_zalloc(sizeof(crypto_rand) * 2 + STRLEN(SOCK_EXTENSION) + 1);
  sprintf(buf, "%x%x%x%x"SOCK_EXTENSION, crypto_rand[0], crypto_rand[1], crypto_rand[2], crypto_rand[3]);
  return buf;
}

int create_domain_client(char *addr)
{
  struct sockaddr_un claddr;
  int sock;
  char *client_addr = NULL;
  socklen_t addrlen = 0;

  os_memset(&claddr, 0, sizeof(struct sockaddr_un));
  claddr.sun_family = AF_UNIX;

  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    log_err("socket");
    return -1;
  }

  if (addr == NULL) {
    if ((client_addr = generate_socket_name()) == NULL) {
      log_trace("generate_socket_name fail");
      return -1;
    }

    strcpy(&claddr.sun_path[1], client_addr);
    addrlen = sizeof(sa_family_t) + strlen(client_addr) + 1;
    os_free(client_addr);
  } else {
    os_strlcpy(claddr.sun_path, addr, sizeof(claddr.sun_path));
    addrlen = sizeof(struct sockaddr_un);
  }

  

  if (bind(sock, (struct sockaddr *) &claddr, addrlen) == -1) {
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

ssize_t read_domain_data(int sock, char *data, size_t data_len,
  struct sockaddr_un *addr, int *addr_len, int flags)
{
  *addr_len = sizeof(struct sockaddr_un);

  if (data == NULL) {
    log_trace("data param is NULL");
    return -1;
  }

  if (addr == NULL) {
    log_trace("addr param is NULL");
    return -1;
  }

  ssize_t num_bytes = recvfrom(sock, data, data_len, flags, (struct sockaddr *) addr, addr_len);
  if (num_bytes == -1) {
    log_err("recvfrom");
    return -1;
  }

  return num_bytes;
}

ssize_t read_domain_data_s(int sock, char *data, size_t data_len, char *addr, int flags)
{
  struct sockaddr_un unaddr;
  ssize_t num_bytes;
  int addr_len;

  if (addr == NULL) {
    log_trace("addr is NULL");
    return -1;
  }

  num_bytes = read_domain_data(sock, data, data_len, &unaddr, &addr_len, flags);

  strcpy(addr, unaddr.sun_path);

  return num_bytes;
}

ssize_t write_domain_data_s(int sock, char *data, size_t data_len, char *addr)
{
  struct sockaddr_un uaddr;

  if (addr == NULL) {
    log_trace("addr param is NULL");
    return -1;
  }

  init_domain_addr(&uaddr, addr);

  return write_domain_data(sock, data, data_len, &uaddr, sizeof(struct sockaddr_un));
}

ssize_t write_domain_data(int sock, char *data, size_t data_len, struct sockaddr_un *addr, int addr_len)
{
  ssize_t num_bytes;

  if (data == NULL) {
    log_trace("data param is NULL");
    return -1;
  }

  if (addr == NULL) {
    log_trace("addr param is NULL");
    return -1;
  }

  errno = 0;
  if ((num_bytes = sendto(sock, data, data_len, 0, (struct sockaddr *) addr, addr_len)) < 0) {
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