/*
    This file is part of mDNS Reflector (mdns-reflector), a lightweight and performant multicast DNS (mDNS) reflector.
    Copyright (C) 2021 Yuxiang Zhu <me@yux.im>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <inttypes.h>

#include "../utils/log.h"
#include "../utils/eloop.h"
#include "../utils/domain.h"
#include "../capture/mdns_decoder.h"

#include "reflector.h"
#include "reflection_list.h"
#include "options.h"
#include "mcast.h"

#if defined(__linux__)

#include <sys/epoll.h>

#elif defined(__unix__) || defined(__APPLE__)
#include <sys/event.h>
#endif
#define MDNS_PORT 5353
#define MDNS_ADDR4 (u_int32_t)0xe00000fb  /* 224.0.0.251 */
#define MDNS_ADDR6_INIT \
{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb }}}

#define PACKET_MAX 10240
#define MAX_EVENTS 10

bool stopping;

int new_recv_socket(const struct sockaddr_storage *sa, socklen_t sa_len, uint32_t ifindex) {
    const int ON = 1;
    int fd;
    switch (sa->ss_family) {
        case AF_INET6:
            fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd == -1) {
                log_err("IPv6 socket");
                return -1;
            }
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ON, sizeof(ON)) == -1) {
                log_err("IPv6 setsockopt IPV6_V6ONLY");
                goto cleanup;
            }
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ON, sizeof(ON)) == -1) {
                log_err("IPv6 setsockopt IPV6_PKTINFO");
                goto cleanup;
            }
#if defined(SO_BINDTODEVICE)
            {
                struct ifreq ifr;
                if (if_indextoname(ifindex, ifr.ifr_ifrn.ifrn_name) == NULL) {
                    log_err("if_indextoname");
                    goto cleanup;
                }
                if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1) {
                    log_err("setsockopt SO_BINDTODEVICE");
                    goto cleanup;
                }
            }
#elif defined(IPV6_BOUND_IF)
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &ifindex, sizeof(ifindex)) == -1) {
                log_err("IPv6 setsockopt IPV6_BOUND_IF");
                goto cleanup;
            }
#endif
            break;
        case AF_INET:
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd == -1) {
                log_err("IPv4 socket");
                return -1;
            }
#if defined(IP_PKTINFO)
            if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &ON, sizeof(ON)) == -1) {
                log_err("IPv4 setsockopt IP_PKTINFO");
                goto cleanup;
            }
#elif defined(IP_RECVDSTADDR)
            if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &ON, sizeof(ON)) == -1) {
                log_err("IPv4 setsockopt IP_RECVDSTADDR");
                goto cleanup;
            }
#endif
#if defined(SO_BINDTODEVICE)
            {
                struct ifreq ifr;
                if (if_indextoname(ifindex, ifr.ifr_ifrn.ifrn_name) == NULL) {
                    log_err("if_indextoname");
                    goto cleanup;
                }
                if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1) {
                    log_err("setsockopt SO_BINDTODEVICE");
                    goto cleanup;
                }
            }
#elif defined(IP_BOUND_IF)
            if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex)) == -1) {
                log_err("IPv4 setsockopt IP_BOUND_IF");
                goto cleanup;
            }
#endif
            break;
        default:
            errno = EAFNOSUPPORT;
            return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ON, sizeof(ON)) == -1) {
        log_err("setsockopt SO_REUSEADDR");
        goto cleanup;
    }
#if defined(SO_REUSEPORT) && !defined(__linux__)
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &ON, sizeof(ON)) == -1) {
        log_err("setsockopt SO_REUSEPORT");
        goto cleanup;
    }
#endif
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_err("fcntl F_GETFL");
        goto cleanup;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_err("fcntl F_SETFL");
        goto cleanup;
    }
    if (bind(fd, (struct sockaddr *) sa, sa_len) == -1) {
        log_err("bind");
        goto cleanup;
    }
    return fd;
    cleanup:
    close(fd);
    return -1;
}

int new_send_socket(const struct sockaddr_storage *sa, socklen_t sa_len, uint32_t ifindex) {
    const int ON = 1;
    const int OFF = 0;
    int fd;
    switch (sa->ss_family) {
        case AF_INET6:
            fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd == -1) {
                log_err("IPv6 socket");
                return -1;
            }
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ON, sizeof(ON)) == -1) {
                log_err("setsockopt IPV6_V6ONLY");
                goto cleanup;
            }
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) == -1) {
                log_err("setsockopt IPV6_MULTICAST_IF");
                goto cleanup;
            }
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &OFF, sizeof(ON)) == -1) {
                log_err("setsockopt IPV6_MULTICAST_LOOP");
                goto cleanup;
            }
            break;
        case AF_INET:
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd == -1) {
                log_err("IPv4 socket");
                return -1;
            }
            {
                struct ifreq ifreq;
                if (if_indextoname(ifindex, ifreq.ifr_name) == NULL) {
                    goto cleanup;
                }
                struct sockaddr_in *src_addr4 = (struct sockaddr_in *) &ifreq.ifr_addr;
                if (ioctl(fd, SIOCGIFADDR, &ifreq) == -1) {
                    goto cleanup;
                }
                if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &src_addr4->sin_addr, sizeof(src_addr4->sin_addr)) ==
                    -1) {
                    log_err("setsockopt IP_MULTICAST_IF");
                    goto cleanup;
                }
            }
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &OFF, sizeof(ON)) == -1) {
                log_err("setsockopt IP_MULTICAST_LOOP");
                goto cleanup;
            }
            break;
        default:
            errno = EAFNOSUPPORT;
            return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ON, sizeof(ON)) == -1) {
        log_err("setsockopt SO_REUSEADDR");
        goto cleanup;
    }
#if defined(SO_REUSEPORT) && !defined(__linux__)
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &ON, sizeof(ON)) == -1) {
        log_err("setsockopt SO_REUSEPORT");
        goto cleanup;
    }
#endif
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_err("fcntl F_GETFL");
        goto cleanup;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        log_err("fcntl F_SETFL");
        goto cleanup;
    }
    if (bind(fd, (struct sockaddr *) sa, sa_len) == -1) {
        log_err("bind");
        goto cleanup;
    }
    return fd;
    cleanup:
    close(fd);
    return -1;
}

int sockaddr2str(struct sockaddr_storage *sa, char *buffer, uint16_t *port) {
  if (sa->ss_family == AF_INET6) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sa;
    if (inet_ntop(AF_INET6, &sa6->sin6_addr, buffer, INET6_ADDRSTRLEN) == NULL) {
      log_err("inet_ntop");
      return -1;
    }

    *port = ntohs(sa6->sin6_port);
  } else if (sa->ss_family == AF_INET) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *) sa;

    if (inet_ntop(AF_INET, &sa4->sin_addr, buffer, INET_ADDRSTRLEN) == NULL) {
      log_err("inet_ntop");
      return -1;
    }

    *port = ntohs(sa4->sin_port);
  } else {
    log_trace("Unknown ss_family");
    return -1;
  }

  return 0;
}

static void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
            stopping = true;
            break;
    }
}

void close_reflector_if(struct reflection_list *rif)
{
  struct reflection_list *el;
  dl_list_for_each(el, &(rif)->list, struct reflection_list, list) {
    if (el->recv_fd > -1) {
      close(el->recv_fd);
    }
    if (el->send_fd) {
      close(el->send_fd);
    }
  }
}

void eloop_reflector_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  struct client_address peer_addr;
  uint32_t bytes_available;
  char *buf;
  ssize_t num_bytes;
  size_t first = 0;
  uint16_t port;
  char peer_addr_str[INET6_ADDRSTRLEN];
  struct mdns_header header;
  char *qname = NULL, *rrname = NULL;

  os_memset(&peer_addr, 0, sizeof(struct client_address));

  if (ioctl(sock, FIONREAD, &bytes_available) == -1) {
    log_err("ioctl");
    return;
  }

  if ((buf = os_malloc(bytes_available)) == NULL) {
    log_err("os_malloc");
    return;
  }

  if ((num_bytes = read_domain_data(sock, buf, bytes_available, &peer_addr, 0)) == -1) {
    log_trace("read_domain_data fail");
    os_free(buf);
    return;
  }

  if (sockaddr2str((struct sockaddr_storage *)&peer_addr.addr, peer_addr_str, &port) < 0) {
    log_trace("sockaddr2str fail");
    os_free(buf);
    return;
  }

  log_trace("Received %u bytes from IP=%s and port=%d", num_bytes, peer_addr_str, port);
  if (decode_mdns_header((uint8_t *)buf, &header) < 0) {
    log_trace("decode_mdns_header fail");
    os_free(buf);
    return;
  }

  if ((size_t) num_bytes < sizeof(struct mdns_header)) {
    log_trace("Not enough bytes to process mdns");
    os_free(buf);
    return;
  }

  first = sizeof(struct mdns_header);
  if (decode_mdns_queries((uint8_t *) buf, (size_t) num_bytes, &first, header.nqueries, &qname) < 0) {
    log_trace("decode_mdns_questions fail");
    os_free(buf);
    return;
  }

  if (decode_mdns_answers((uint8_t *) buf, (size_t) num_bytes, &first, header.nanswers, &rrname) < 0) {
    log_trace("decode_mdns_questions fail");
    os_free(buf);
    if (qname != NULL) {
      os_free(qname);
    }
    return;
  }
  os_free(buf);

  log_trace("mDNS id=%d flags=0x%x nqueries=%d nanswers=%d nauth=%d nother=%d qname=%s rrname=%s",
    header.tid, header.flags, header.nqueries, header.nanswers,
    header.nauth, header.nother, qname, rrname);

  if (qname != NULL) {
    os_free(qname);
  }
  if (rrname != NULL) {
    os_free(rrname);
  }
}

int register_reflector_if6(/*int epoll_fd, */struct reflection_list *rif)
{
  // struct epoll_event ev;
  // ev.events = EPOLLIN;
  
  struct reflection_list *el;
  struct sockaddr_in6 sa6 = {
    .sin6_family=AF_INET6,
    .sin6_port = htons(MDNS_PORT),
    .sin6_addr = IN6ADDR_ANY_INIT,
  };

  struct sockaddr_in6 sa_group6 = {
    .sin6_family=AF_INET6,
    .sin6_port = htons(MDNS_PORT),
    .sin6_addr = MDNS_ADDR6_INIT,
  };

  dl_list_for_each(el, &rif->list, struct reflection_list, list) {
    log_trace("Configuring IP6 for ifname=%s ifindex=%d", el->ifname, el->ifindex);
    el->send_fd = new_send_socket((struct sockaddr_storage *) &sa6, sizeof(sa6), el->ifindex);
    if (el->send_fd < 0) {
      log_trace("new_send_socket fail for interface %s", el->ifname);
      return -1;
    }
    el->recv_fd = new_recv_socket((struct sockaddr_storage *) &sa6, sizeof(sa6), el->ifindex);
    if (el->recv_fd < 0) {
      log_trace("new_recv_socket fail for interface %s", el->ifname);
      return -1;
    }

    if (eloop_register_read_sock(el->recv_fd, eloop_reflector_handler, (void *) el, (void *) rif) < 0) {
      log_trace("eloop_register_read_sock fail");
      return -1;
    }

    // ev.data.ptr = el;
    // if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, el->recv_fd, &ev) == -1) {
    //   log_err("epoll_ctl EPOLL_CTL_ADD");
    //   return -1;
    // }

    sa_group6.sin6_scope_id = el->ifindex;
    if (mcast_join(el->recv_fd, (struct sockaddr_storage *) &sa_group6, sizeof(sa_group6), el->ifindex) < 0) {
      log_err("Failed to join interface %s to IPv6 multicast group", el->ifname);
      return -1;
    }
  }
  return 0;
}

int register_reflector_if4(/*int epoll_fd, */struct reflection_list *rif)
{
  // struct epoll_event ev;
  // ev.events = EPOLLIN;

  struct reflection_list *el;
  struct sockaddr_in sa4 = {
    .sin_family = AF_INET,
    .sin_port = htons(MDNS_PORT),
    .sin_addr.s_addr = htonl(INADDR_ANY),
  };

  struct sockaddr_in sa_group4 = {
    .sin_family = AF_INET,
    .sin_port = htons(MDNS_PORT),
    .sin_addr.s_addr = htonl(MDNS_ADDR4),
  };

  dl_list_for_each(el, &rif->list, struct reflection_list, list) {
    log_trace("Configuring IP4 for ifname=%s ifindex=%d", el->ifname, el->ifindex);
    el->send_fd = new_send_socket((struct sockaddr_storage *) &sa4, sizeof(sa4), el->ifindex);
    if (el->send_fd < 0) {
      log_trace("new_send_socket fail for interface %s", el->ifname);
      return -1;
    }

    el->recv_fd = new_recv_socket((struct sockaddr_storage *) &sa4, sizeof(sa4), el->ifindex);
    if (el->recv_fd < 0) {
      log_trace("new_send_socket fail for interface %s", el->ifname);
      return -1;
    }

    if (eloop_register_read_sock(el->recv_fd, eloop_reflector_handler, (void *) el, (void *) rif) < 0) {
      log_trace("eloop_register_read_sock fail");
      return -1;
    }

    // ev.data.ptr = el;
    // if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, el->recv_fd, &ev) == -1) {
    //   log_err("epoll_ctl EPOLL_CTL_ADD");
    //   return -1;
    // }

    if (mcast_join(el->recv_fd, (struct sockaddr_storage *) &sa_group4, sizeof(sa_group4), el->ifindex) < 0) {
      log_err("Failed to join interface %s to IPv4 multicast group", el->ifname);
      return -1;
    }
  }
  
  return 0;
}

int run_event_loop(struct options *options) {
  int r = -1;
  struct reflection_list *rif, *drif;

  // signal(SIGTERM, signal_handler);
  // int epoll_fd = epoll_create1(0);
  // if (epoll_fd == -1) {
  //   log_err("epoll_create1");
  //   return -1;
  // }
  // struct epoll_event ev, events[MAX_EVENTS];
  // ev.events = EPOLLIN;

  // Create recv_socks and send_socks for IPv6 reflection zones.
  struct sockaddr_in6 sa_group6 = {
    .sin6_family=AF_INET6,
    .sin6_port = htons(MDNS_PORT),
    .sin6_addr = MDNS_ADDR6_INIT,
  };

  struct sockaddr_in sa_group4 = {
    .sin_family = AF_INET,
    .sin_port = htons(MDNS_PORT),
    .sin_addr.s_addr = htonl(MDNS_ADDR4),
  };

  if (register_reflector_if6(/*epoll_fd, */options->rif6) < 0) {
    log_trace("register_reflector_if6 fail");
    close_reflector_if(options->rif6);
    return -1;
  }

  if (register_reflector_if4(/*epoll_fd, */options->rif4) < 0) {
    log_trace("register_reflector_if4 fail");
    close_reflector_if(options->rif6);
    close_reflector_if(options->rif4);
    return -1;
  }

  eloop_run();
    // struct sockaddr_storage peer_addr;
    // char peer_addr_str[INET6_ADDRSTRLEN + 2 + 1 + 5 + 1 + 10];
    // char buffer[PACKET_MAX];
    // char cmbuf[0x100];
    // struct iovec iov = {
    //   .iov_base = buffer,
    //   .iov_len = sizeof(buffer),
    // };
    // struct msghdr mh = {
    //   .msg_name = &peer_addr,
    //   .msg_namelen = sizeof(peer_addr),
    //   .msg_iov = &iov,
    //   .msg_iovlen = 1,
    //   .msg_control = cmbuf,
    //   .msg_controllen = sizeof(cmbuf),
    // };

    // while (!stopping) {
    //   log_trace("epoll_wait");
    //   int nevents = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    //   if (nevents == -1) {
    //     log_err("epoll_wait");
    //     goto end;
    //   }

    //   for (int i = 0; i < nevents; ++i) {
    //     struct reflection_list *rif = events[i].data.ptr;
    //     int fd = rif->recv_fd;

    //     for (;;) {
    //       log_trace("recvmsg");
    //       ssize_t recv_size = recvmsg(fd, &mh, 0);
    //       if (recv_size == -1) {
    //         if (errno == EWOULDBLOCK)
    //           break;
    //         log_err("recvfrom");
    //         goto end;
    //       }

    //       snprintf(peer_addr_str, sizeof(peer_addr_str), "%s", sockaddr_storage_to_string(&peer_addr));
    //       log_trace("received %u bytes from interface %s with source IP %s", recv_size, rif->ifname, peer_addr_str);

    //       if (recv_size >= PACKET_MAX) {
    //         log_trace("ignoring because it is too large (limit is %d bytes)", PACKET_MAX);
    //         continue;
    //       }

    //       // Send to other interfaces.
    //       struct sockaddr *dst;
    //       socklen_t dst_len;
    //       if (peer_addr.ss_family == AF_INET6) {
    //         dst = (struct sockaddr *) &sa_group6;
    //         dst_len = sizeof(sa_group6);
    //       } else if (peer_addr.ss_family == AF_INET) {
    //         dst = (struct sockaddr *) &sa_group4;
    //         dst_len = sizeof(sa_group4);
    //       } else {
    //         log_trace("ignoring packet from unknown address family: %d", peer_addr.ss_family);
    //         continue;
    //       }
          
    //       if (peer_addr.ss_family == AF_INET6) {
    //         dl_list_for_each(drif, &(options->rif6)->list, struct reflection_list, list) {
    //           if (drif == rif){
    //             continue;
    //           }
    //           sa_group6.sin6_scope_id = drif->ifindex;
    //           log_trace("forwarding to interface %s", drif->ifname);

    //           if (sendto(drif->send_fd, buffer, (size_t) recv_size, 0, dst, dst_len) == -1) {
    //             if (errno == EWOULDBLOCK) {
    //               continue;  // send queue overwhelmed; skipping
    //             }
    //             log_err("sendto");
    //             goto end;
    //           }

    //           log_trace("sent");
    //         }
    //       } else {
    //         dl_list_for_each(drif, &(options->rif4)->list, struct reflection_list, list) {
    //           if (drif == rif)
    //             continue;

    //           log_trace("forwarding to interface %s", drif->ifname);

    //           if (sendto(drif->send_fd, buffer, (size_t) recv_size, 0, dst, dst_len) == -1) {
    //             if (errno == EWOULDBLOCK) {
    //               continue;  // send queue overwhelmed; skipping
    //             }
    //             log_err("sendto");
    //             goto end;
    //           }

    //           log_trace("sent");
    //         }
    //       }
    //     }
    //   }
    // }

    // r = 0;

end:
  close_reflector_if(options->rif6);
  close_reflector_if(options->rif4);

  // close(epoll_fd);
  return r;
}
