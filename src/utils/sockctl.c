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
#include <limits.h> // for PATH_MAX
#include <libgen.h> // for dirname()

#include "sockctl.h"

#include "allocs.h"
#include "os.h"
#include "log.h"
#include "net.h"

#define SOCK_EXTENSION ".sock"
#define TMP_UNIX_SOCK_FOLDER_PREFIX "/tmp/edgesec/tmp-unix-socks."
/** Template for mkdtemp() to create tmp folders for temporary unix domain
 * sockets */
#define TMP_UNIX_SOCK_FOLDER_TEMPLATE TMP_UNIX_SOCK_FOLDER_PREFIX "XXXXXX"
/** Basename for temporary unix domain sockets */
#define TMP_UNIX_SOCK_NAME "client-socket" SOCK_EXTENSION
#define DOMAIN_REPLY_TIMEOUT 10

void init_domain_addr(struct sockaddr_un *unaddr, const char *addr) {
  *unaddr = (struct sockaddr_un){.sun_family = AF_UNIX};
  os_strlcpy(unaddr->sun_path, addr, sizeof(unaddr->sun_path));
}

/**
 * @brief Creates a path for a temporary domain socket.
 *
 * Creates a temporary folder using `mkdtemp()`, then returns a path
 * within that folder.
 *
 * @return A path that can be used to create a temporary domain socket.
 * @retval NULL on error (see @p errno).
 * @post Please free() the returned string.
 * @post Please delete the temporary folder,
 * e.g. by using cleanup_tmp_domain_socket_path()
 */
static const char *create_tmp_domain_socket_path() {
  char socket_dir[] = TMP_UNIX_SOCK_FOLDER_TEMPLATE;
  if (make_dirs_to_path(socket_dir, 0755)) {
    log_errno("Failed to make_dirs_to_path(%s, 0755)", socket_dir);
  }
  if (mkdtemp(socket_dir) == NULL) {
    log_errno("Failed to mkdtemp %s", socket_dir);
    return NULL;
  }

  // Can we make this `const`?
  char socket_name[] = TMP_UNIX_SOCK_NAME;
  return concat_paths(socket_dir, socket_name);
}

/**
 * @brief Cleans up the given @p socket_path.
 *
 * Performs extra cleanup if the @p socket_path was created with
 * create_tmp_domain_socket_path().
 *
 * @param socket_path The path to the socket to cleanup.
 * @retval -1 On error.
 * @retval  0 Success, cleaned up @p socket_path.
 */
static int cleanup_tmp_domain_socket_path(const char *socket_path) {
  if (unlink(socket_path)) {
    log_errno("Failed to unlink() %d", socket_path);
    return -1;
  }
  if (strncmp(TMP_UNIX_SOCK_FOLDER_PREFIX, socket_path,
              sizeof(TMP_UNIX_SOCK_FOLDER_PREFIX) - 1) != 0) {
    // **NOT** created create_tmp_domain_socket_path()
    return 0;
  }

  // need to make a non-const copy of path since dirname() may change
  // stirng contents
  char path[PATH_MAX];
  path[PATH_MAX - 1] = '\0'; // ensure string is always NUL terminated
  strncpy(path, socket_path, PATH_MAX - 1);

  char *socket_dir = dirname(path);

  log_debug("Deleting folder %s, as it looks like it was created by "
            "create_tmp_domain_socket_path()",
            socket_dir);
  // only deletes empty directories, not empty dirs set errno to ENOTEMPTY
  if (rmdir(socket_dir)) {
    log_errno("Failed to rmdir() tmp unix socket folder %s", socket_dir);
    return -1;
  }
  return 0;
}

int create_domain_client(const char *path) {
  socklen_t addrlen = 0;
  struct sockaddr_un claddr = {.sun_family = AF_UNIX};
  int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    log_errno("socket");
    return -1;
  }

  if (path == NULL) {
#ifdef USE_ABSTRACT_UNIX_DOMAIN_SOCKETS
    (void)&create_tmp_domain_socket_path; // not used if
                                          // USE_ABSTRACT_UNIX_DOMAIN_SOCKETS is
                                          // set
    // Setting addrlen to `sizeof(sa_family_t)` will autobind
    // the Unix domain socket to a random 5-hex character long
    // abstract address (2^20 autobind addresses)
    // See https://manpages.ubuntu.com/manpages/jammy/en/man7/unix.7.html
    addrlen = sizeof(sa_family_t);
#else // standard POSIX
    const char *tmp_socket_path = create_tmp_domain_socket_path();
    if (tmp_socket_path == NULL) {
      log_errno("Failed to create temporary unix domain socket.");
      return -1;
    }
    os_strlcpy(claddr.sun_path, tmp_socket_path, sizeof(claddr.sun_path));
    addrlen = sizeof(struct sockaddr_un);
#endif
  } else {
    os_strlcpy(claddr.sun_path, path, sizeof(claddr.sun_path));
    addrlen = sizeof(struct sockaddr_un);
  }

  if (bind(sock, (struct sockaddr *)&claddr, addrlen) == -1) {
    log_errno("bind");
    close(sock);
    return -1;
  }

  return sock;
}

int create_domain_server(const char *server_path) {
  int sfd = socket(AF_UNIX, SOCK_DGRAM, 0); /* Create server socket */
  if (sfd == -1) {
    log_errno("socket");
    return -1;
  }

  /* Construct well-known address and bind server socket to it */

  /* For an explanation of the following check, see the erratum note for
     page 1168 at http://www.man7.org/tlpi/errata/.
  */
  struct sockaddr_un svaddr;
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

int close_domain_socket(int unix_domain_socket_fd) {
  struct sockaddr_un sockaddr = {0};
  socklen_t address_len = sizeof(sockaddr);
  if (getsockname(unix_domain_socket_fd, (struct sockaddr *)&sockaddr,
                  &address_len)) {
    log_errno("Failed to getsockname for unix domain socket %d",
              unix_domain_socket_fd);
    return -1;
  }
  if (sockaddr.sun_family != AF_UNIX) {
    log_error("Socket %d is not a unix domain socket, instead it's a %d",
              unix_domain_socket_fd, sockaddr.sun_family);
    return -1;
  }
  if (address_len >=
          sizeof(sa_family_t) &&   // unbound/_unnamed_ unix domain socket
      sockaddr.sun_path[0] != '\0' // _abstract_ unix domain socket (Linux only)
  ) {
    // Unix domain socket is type _pathname_
    if (cleanup_tmp_domain_socket_path(sockaddr.sun_path)) {
      log_errno("Failed to cleanup unix domain socket at %s",
                sockaddr.sun_path);
      return -1;
    }
  }
  return close(unix_domain_socket_fd);
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

ssize_t write_domain_data_s(int sock, const char *data, size_t data_len,
                            const char *addr) {
  if (addr == NULL) {
    log_error("addr param is NULL");
    return -1;
  }

  struct client_address claddr;
  init_domain_addr(&claddr.caddr.addr_un, addr);
  claddr.len = sizeof(struct sockaddr_un);
  claddr.type = SOCKET_TYPE_DOMAIN;

  return write_socket_data(sock, data, data_len, &claddr);
}

ssize_t write_socket_domain(int sock, const char *data, size_t data_len,
                            const struct client_address *addr) {
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

ssize_t write_socket_udp(int sock, const char *data, size_t data_len,
                         const struct client_address *addr) {
  ssize_t sent;
  char ip[OS_INET_ADDRSTRLEN];

  if (inaddr4_2_ip(&addr->caddr.addr_in.sin_addr, ip) == NULL) {
    log_errno("inet_ntop");
    return -1;
  }

  log_trace("Sending to udp socket on %s:%d", ip, addr->caddr.addr_in.sin_port);
  if ((sent = sendto(sock, data, data_len, 0,
                     (const struct sockaddr *)&addr->caddr.addr_in,
                     addr->len)) < 0) {
    log_errno("sendto");
    return -1;
  }

  return sent;
}

ssize_t write_socket_data(int sock, const char *data, size_t data_len,
                          const struct client_address *addr) {
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

int writeread_domain_data_str(char *socket_path, const char *write_str,
                              char **reply) {
  *reply = NULL;

  int sfd = create_domain_client(NULL);
  if (sfd == -1) {
    log_error("create_domain_client fail");
    return -1;
  }

  int return_code = -1;

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(sfd, &readfds);

  log_trace("Sending to socket_path=%s", socket_path);
  ssize_t send_count =
      write_domain_data_s(sfd, write_str, strlen(write_str), socket_path);
  if (send_count < 0) {
    log_errno("sendto");
    goto cleanup_sfd;
  }

  if ((size_t)send_count != strlen(write_str)) {
    log_errno("write_domain_data_s fail");
    goto cleanup_sfd;
  }

  log_trace("Sent %d bytes to %s", send_count, socket_path);

  errno = 0;
  struct timeval timeout = {
      .tv_sec = DOMAIN_REPLY_TIMEOUT,
      .tv_usec = 0,
  };
  if (select(sfd + 1, &readfds, NULL, NULL, &timeout) < 0) {
    log_errno("select");
    goto cleanup_sfd;
  }

  if (!FD_ISSET(sfd, &readfds)) {
    // select() returned 0
    log_error("Socket timeout");
    goto cleanup_sfd;
  }

  uint32_t bytes_available;
  if (ioctl(sfd, FIONREAD, &bytes_available) == -1) {
    log_errno("ioctl");
    goto cleanup_sfd;
  }

  log_trace("Socket received bytes available=%u", bytes_available);
  char *rec_data = os_zalloc(bytes_available + 1);
  if (rec_data == NULL) {
    log_errno("os_zalloc");
    goto cleanup_sfd;
  }

  ssize_t rec_count = read_domain_data_s(sfd, rec_data, bytes_available,
                                         socket_path, MSG_DONTWAIT);

  if (rec_count < 0) {
    log_error("read_domain_data_s fail");
    goto cleanup_recdata;
  }

  // rtrim modifies the input string.
  (void)rtrim(rec_data, NULL);

  char *trimmed_data = os_realloc(rec_data, strlen(rec_data) + 1);
  if (trimmed_data == NULL) {
    log_errno("os_realloc failed to relloc string %s", rec_data);
    goto cleanup_recdata;
  }
  // set to NULL so free(rec_data) does nothing
  rec_data = NULL;

  return_code = 0;
  *reply = trimmed_data;

cleanup_recdata:
  os_free(rec_data);
cleanup_sfd:
  close_domain_socket(sfd);
  return return_code;
}
