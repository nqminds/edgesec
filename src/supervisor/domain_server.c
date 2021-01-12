/**************************************************************************************************
*  Filename:        domain_server.c
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     domain_server source file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>

#include "utils/os.h"
#include "utils/log.h"

void init_domain_addr(struct sockaddr_un *unaddr, char *addr)
{
  os_memset(unaddr, 0, sizeof(struct sockaddr_un));
  unaddr->sun_family = AF_UNIX;
  strncpy(unaddr->sun_path, addr, sizeof(unaddr->sun_path) - 1);
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
