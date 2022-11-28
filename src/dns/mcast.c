/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of mDNS utils.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "../utils/log.h"
#include "../utils/sockctl.h"

#include "mcast.h"

int join_mcast(int fd, const struct sockaddr_storage *sa, socklen_t sa_len,
               uint32_t ifindex) {
  int level;
  struct group_req req;
  struct ip_mreq mreq4;
  struct ifreq ifreq;

#if defined(MCAST_JOIN_GROUP)
  switch (sa->ss_family) {
    case AF_INET6:
      level = IPPROTO_IPV6;
      break;
    case AF_INET:
      level = IPPROTO_IP;
      break;
    default:
      errno = EAFNOSUPPORT;
      return -1;
  }

  req.gr_interface = ifindex;
  memcpy(&req.gr_group, sa, sa_len);

#if defined(__unix__) && !defined(__linux__) || defined(__APPLE__)
  // At least FreeBSD and macOS requires ss_len, otherwise we'll get an `Invalid
  // argument` error.
  req.gr_group.ss_len = (uint8_t)sa_len;
#endif
  (void)ifreq;
  (void)mreq4;
  if (setsockopt(fd, level, MCAST_JOIN_GROUP, &req, sizeof(struct group_req)) <
      0) {
    log_errno("setsockopt");
    return -1;
  }
#else
  (void)sa_len;

  switch (sa->ss_family) {
    case AF_INET6: {
      struct ipv6_mreq mreq6;
      mreq6.ipv6mr_interface = ifindex;
      memcpy(&mreq6.ipv6mr_multiaddr, &((struct sockaddr_in6 *)sa)->sin6_addr,
             sizeof(struct in6_addr));
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) <
          0) {
        log_errno("setsockopt") return -1;
      }
      break;
    }
    case AF_INET: {
      if (ifindex > 0) {
        if (if_indextoname(ifindex, ifreq.ifr_name) == NULL) {
          log_errno("if_indextoname") return -1;
        }

        if (ioctl(fd, SIOCGIFADDR, &ifreq) == -1) {
          log_errno("ioctl") return -1;
        }

        memcpy(&mreq4.imr_interface,
               &((struct sockaddr_in *)&ifreq.ifr_ifru.ifru_addr)->sin_addr,
               sizeof(struct in_addr));
      } else {
        mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
      }
      memcpy(&mreq4.imr_multiaddr, &((struct sockaddr_in *)sa)->sin_addr,
             sizeof(struct in_addr));
      if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq4, sizeof(mreq4)) <
          0) {
        log_errno("setsockopt") return -1;
      }
      break;
    }
    default:
      errno = EAFNOSUPPORT;
      return -1;
  }
#endif

  return 0;
}

int create_recv_mcast(const struct sockaddr_storage *sa, socklen_t sa_len,
                      uint32_t ifindex) {
  struct ifreq ifr;
  int on = 1;
  int fd, flags;

  errno = 0;
  switch (sa->ss_family) {
    case AF_INET6:
      if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        log_errno("socket");
        close(fd);
        return -1;
      }

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
#if defined(SO_BINDTODEVICE)
      if (if_indextoname(ifindex, ifr.ifr_ifrn.ifrn_name) == NULL) {
        log_errno("if_indextoname");
        close(fd);
        return -1;
      }

      if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
#elif defined(IPV6_BOUND_IF)
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &ifindex,
                     sizeof(ifindex)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
#else
      (void)ifindex; /* binding a socket to a specific interface is very
                        complicated for except for Linux/Darwin */
#endif
      break;
    case AF_INET:
      if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        log_errno("socket");
        return -1;
      }
#if defined(IP_PKTINFO)
      if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
#elif defined(IP_RECVDSTADDR)
      if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
#endif
#if defined(SO_BINDTODEVICE)
      if (if_indextoname(ifindex, ifr.ifr_ifrn.ifrn_name) == NULL) {
        log_errno("if_indextoname");
        close(fd);
        return -1;
      }

      if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
#elif defined(IP_BOUND_IF)
      if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex)) <
          0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
#endif
      break;
    default:
      errno = EAFNOSUPPORT;
      return -1;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    log_errno("setsockopt");
    close(fd);
    return -1;
  }
#if defined(SO_REUSEPORT) && !defined(__linux__)
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
    log_errno("setsockopt");
    close(fd);
    return -1;
  }
#endif
  if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
    log_errno("fcntl");
    close(fd);
    return -1;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    log_errno("fcntl");
    close(fd);
    return -1;
  }

  if (bind(fd, (struct sockaddr *)sa, sa_len) < 0) {
    log_errno("bind");
    close(fd);
    return -1;
  }

  return fd;
}

int create_send_mcast(const struct sockaddr_storage *sa, socklen_t sa_len,
                      uint32_t ifindex) {
  int on = 1;
  int off = 0;
  int fd, flags;
  struct ifreq ifreq;
  struct sockaddr_in *src_addr4;

  switch (sa->ss_family) {
    case AF_INET6:
      if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        log_errno("socket");
        return -1;
      }

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex,
                     sizeof(ifindex)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &off, sizeof(off)) <
          0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }

      break;
    case AF_INET:
      if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        log_errno("socket");
        return -1;
      }

      if (if_indextoname(ifindex, ifreq.ifr_name) == NULL) {
        close(fd);
        return -1;
      }

      src_addr4 = (struct sockaddr_in *)&ifreq.ifr_addr;

      if (ioctl(fd, SIOCGIFADDR, &ifreq) < 0) {
        close(fd);
        return -1;
      }

      if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &src_addr4->sin_addr,
                     sizeof(src_addr4->sin_addr)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }

      if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(on)) < 0) {
        log_errno("setsockopt");
        close(fd);
        return -1;
      }
      break;
    default:
      errno = EAFNOSUPPORT;
      return -1;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    log_errno("setsockopt");
    close(fd);
    return -1;
  }
#if defined(SO_REUSEPORT) && !defined(__linux__)
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
    log_errno("setsockopt");
    close(fd);
    return -1;
  }
#endif
  if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
    log_errno("fcntl");
    close(fd);
    return -1;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    log_errno("fcntl");
    close(fd);
    return -1;
  }

  if (bind(fd, (struct sockaddr *)sa, sa_len) < 0) {
    log_errno("bind");
    close(fd);
    return -1;
  }

  return fd;
}
