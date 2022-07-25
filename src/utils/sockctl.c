/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the socket control utils.
 */

#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "sockctl.h"

#include "allocs.h"
#include "os.h"
#include "log.h"
#include "net.h"

#define SOCK_EXTENSION ".sock"

#define DOMAIN_REPLY_TIMEOUT 10

void init_domain_addr(struct sockaddr_un *unaddr, char *addr) {
  os_memset(unaddr, 0, sizeof(struct sockaddr_un));
  unaddr->sun_family = AF_UNIX;
  os_strlcpy(unaddr->sun_path, addr, sizeof(unaddr->sun_path));
}

char *generate_socket_name(void) {
  unsigned char crypto_rand[4];
  char *buf = NULL;
  if (os_get_random(crypto_rand, 4) == -1) {
    log_error("os_get_random fail");
    return NULL;
  }
  buf = os_zalloc(sizeof(crypto_rand) * 2 + ARRAY_SIZE(SOCK_EXTENSION) + 1);
  sprintf(buf, "%x%x%x%x" SOCK_EXTENSION, crypto_rand[0], crypto_rand[1],
          crypto_rand[2], crypto_rand[3]);
  return buf;
}

int create_domain_client(char *addr) {
  struct sockaddr_un claddr;
  int sock;
  char *client_addr = NULL;
  socklen_t addrlen = 0;

  os_memset(&claddr, 0, sizeof(struct sockaddr_un));
  claddr.sun_family = AF_UNIX;

  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    log_errno("socket");
    return -1;
  }

  if (addr == NULL) {
    if ((client_addr = generate_socket_name()) == NULL) {
      log_error("generate_socket_name fail");
      close(sock);
      return -1;
    }

    strcpy(&claddr.sun_path[1], client_addr);
    addrlen = sizeof(sa_family_t) + strlen(client_addr) + 1;
    os_free(client_addr);
  } else {
    os_strlcpy(claddr.sun_path, addr, sizeof(claddr.sun_path));
    addrlen = sizeof(struct sockaddr_un);
  }

  if (bind(sock, (struct sockaddr *)&claddr, addrlen) == -1) {
    log_errno("bind");
    close(sock);
    return -1;
  }

  return sock;
}

int create_domain_server(char *server_path) {
  struct sockaddr_un svaddr;
  int sfd;

  sfd = socket(AF_UNIX, SOCK_DGRAM, 0); /* Create server socket */
  if (sfd == -1) {
    log_errno("socket");
    return -1;
  }

  /* Construct well-known address and bind server socket to it */

  /* For an explanation of the following check, see the erratum note for
     page 1168 at http://www.man7.org/tlpi/errata/.
  */
  if (strlen(server_path) > sizeof(svaddr.sun_path) - 1) {
    log_error("Server socket path too long: %s", server_path);
    close(sfd);
    return -1;
  }

  if (remove(server_path) == -1 && errno != ENOENT) {
    log_errno("remove-%s", server_path);
    close(sfd);
    return -1;
  }

  init_domain_addr(&svaddr, server_path);

  if (bind(sfd, (struct sockaddr *)&svaddr, sizeof(struct sockaddr_un)) == -1) {
    log_errno("bind");
    close(sfd);
    return -1;
  }

  return sfd;
}

int create_udp_server(unsigned int port) {
  struct sockaddr_in svaddr;
  int sfd;

  /* Create server socket */
  sfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sfd == -1) {
    log_errno("socket");
    return -1;
  }

  /* Turn off Path MTU discovery on IPv4/UDP sockets. */
  if (disable_pmtu_discovery(sfd) < 0) {
    log_error("disable_pmtu_discovery fail");
    close(sfd);
    return -1;
  }

  os_memset(&svaddr, 0, sizeof(struct sockaddr_in));
  svaddr.sin_family = AF_INET;
  svaddr.sin_port = htons(port);

  if (bind(sfd, (struct sockaddr *)&svaddr, sizeof(struct sockaddr_in)) == -1) {
    log_errno("bind");
    close(sfd);
    return -1;
  }

  return sfd;
}

ssize_t read_socket_domain(int sock, char *data, size_t data_len,
                           struct client_address *addr, int flags) {
  ssize_t received;

  addr->len = sizeof(struct sockaddr_un);
  received = recvfrom(sock, data, data_len, flags,
                      (struct sockaddr *)&addr->caddr.addr_un,
                      (socklen_t *)&addr->len);

  if (received == -1) {
    log_errno("recvfrom");
    return -1;
  }

  return received;
}

ssize_t read_socket_udp(int sock, char *data, size_t data_len,
                        struct client_address *addr, int flags) {
  ssize_t received;

  addr->len = sizeof(struct sockaddr_in);
  received = recvfrom(sock, data, data_len, flags,
                      (struct sockaddr *)&addr->caddr.addr_in,
                      (socklen_t *)&addr->len);

  if (received == -1) {
    log_errno("recvfrom");
    return -1;
  }

  return received;
}

ssize_t read_socket_data(int sock, char *data, size_t data_len,
                         struct client_address *addr, int flags) {
  if (data == NULL) {
    log_error("data param is NULL");
    return -1;
  }

  if (addr == NULL) {
    log_error("addr param is NULL");
    return -1;
  }

  switch (addr->type) {
    case SOCKET_TYPE_DOMAIN:
      return read_socket_domain(sock, data, data_len, addr, flags);
    case SOCKET_TYPE_UDP:
      return read_socket_udp(sock, data, data_len, addr, flags);
    default:
      log_error("socket type not specified");
      return -1;
  }
}

ssize_t read_domain_data_s(int sock, char *data, size_t data_len, char *addr,
                           int flags) {
  struct client_address claddr;
  ssize_t num_bytes;

  if (addr == NULL) {
    log_error("addr is NULL");
    return -1;
  }

  claddr.type = SOCKET_TYPE_DOMAIN;

  num_bytes = read_socket_data(sock, data, data_len, &claddr, flags);

  strcpy(addr, claddr.caddr.addr_un.sun_path);

  return num_bytes;
}

ssize_t write_domain_data_s(int sock, char *data, size_t data_len, char *addr) {
  struct client_address claddr;

  if (addr == NULL) {
    log_error("addr param is NULL");
    return -1;
  }

  init_domain_addr(&claddr.caddr.addr_un, addr);
  claddr.len = sizeof(struct sockaddr_un);
  claddr.type = SOCKET_TYPE_DOMAIN;

  return write_socket_data(sock, data, data_len, &claddr);
}

ssize_t write_socket_domain(int sock, char *data, size_t data_len,
                            struct client_address *addr) {
  ssize_t sent;

  log_trace("Sending to domain socket on %.*s", addr->len,
            addr->caddr.addr_un.sun_path);
  if ((sent = sendto(sock, data, data_len, 0,
                     (struct sockaddr *)&addr->caddr.addr_un, addr->len)) < 0) {
    log_errno("sendto");
    return -1;
  }

  return sent;
}

ssize_t write_socket_udp(int sock, char *data, size_t data_len,
                         struct client_address *addr) {
  ssize_t sent;
  char ip[OS_INET_ADDRSTRLEN];

  if (inaddr4_2_ip(&addr->caddr.addr_in.sin_addr, ip) == NULL) {
    log_errno("inet_ntop");
    return -1;
  }

  log_trace("Sending to udp socket on %s:%d", ip, addr->caddr.addr_in.sin_port);
  if ((sent = sendto(sock, data, data_len, 0,
                     (struct sockaddr *)&addr->caddr.addr_in, addr->len)) < 0) {
    log_errno("sendto");
    return -1;
  }

  return sent;
}

ssize_t write_socket_data(int sock, char *data, size_t data_len,
                          struct client_address *addr) {
  if (data == NULL) {
    log_error("data param is NULL");
    return -1;
  }

  if (addr == NULL) {
    log_error("addr param is NULL");
    return -1;
  }

  switch (addr->type) {
    case SOCKET_TYPE_DOMAIN:
      return write_socket_domain(sock, data, data_len, addr);
    case SOCKET_TYPE_UDP:
      return write_socket_udp(sock, data, data_len, addr);
    default:
      log_error("socket type not specified");
      return -1;
  }
}

int writeread_domain_data_str(char *socket_path, char *write_str,
                              char **reply) {
  int sfd;
  uint32_t bytes_available;
  ssize_t send_count, rec_count;
  struct timeval timeout;
  fd_set readfds, masterfds;
  char *rec_data, *trimmed;
  timeout.tv_sec = DOMAIN_REPLY_TIMEOUT;
  timeout.tv_usec = 0;

  *reply = NULL;

  if ((sfd = create_domain_client(NULL)) == -1) {
    log_error("create_domain_client fail");
    return -1;
  }

  FD_ZERO(&masterfds);
  FD_SET(sfd, &masterfds);
  os_memcpy(&readfds, &masterfds, sizeof(fd_set));

  log_trace("Sending to socket_path=%s", socket_path);
  send_count =
      write_domain_data_s(sfd, write_str, strlen(write_str), socket_path);
  if (send_count < 0) {
    log_errno("sendto");
    close(sfd);
    return -1;
  }

  if ((size_t)send_count != strlen(write_str)) {
    log_errno("write_domain_data_s fail");
    close(sfd);
    return -1;
  }

  log_trace("Sent %d bytes to %s", send_count, socket_path);

  errno = 0;
  if (select(sfd + 1, &readfds, NULL, NULL, &timeout) < 0) {
    log_errno("select");
    close(sfd);
    return -1;
  }

  if (FD_ISSET(sfd, &readfds)) {
    if (ioctl(sfd, FIONREAD, &bytes_available) == -1) {
      log_errno("ioctl");
      close(sfd);
      return -1;
    }

    log_trace("Socket received bytes available=%u", bytes_available);
    rec_data = os_zalloc(bytes_available + 1);
    if (rec_data == NULL) {
      log_errno("os_zalloc");
      close(sfd);
      return -1;
    }

    rec_count = read_domain_data_s(sfd, rec_data, bytes_available, socket_path,
                                   MSG_DONTWAIT);

    if (rec_count < 0) {
      log_error("read_domain_data_s fail");
      close(sfd);
      os_free(rec_data);
      return -1;
    }

    if ((trimmed = rtrim(rec_data, NULL)) == NULL) {
      log_error("rtrim fail");
      close(sfd);
      os_free(rec_data);
      return -1;
    }

    *reply = os_strdup(trimmed);
  } else {
    log_error("Socket timeout");
    close(sfd);
    return -1;
  }

  close(sfd);
  os_free(rec_data);

  return 0;
}
