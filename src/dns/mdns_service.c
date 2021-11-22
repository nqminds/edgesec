/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file mdns_service.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of mDNS service structures.
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

#include "../utils/uthash.h"
#include "../utils/if.h"
#include "../utils/log.h"
#include "../utils/eloop.h"
#include "../utils/domain.h"
#include "../capture/mdns_decoder.h"
#include "../supervisor/supervisor_config.h"

#include "mdns_service.h"
#include "reflection_list.h"
#include "mcast.h"

#define MDNS_PORT       5353
#define MDNS_ADDR4      (uint32_t)0xE00000FB  /* 224.0.0.251 */
#define MDNS_ADDR6_INIT \
{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb }}}

static const UT_icd mdns_answers_icd = {sizeof(struct mdns_answer_entry), NULL, NULL, NULL};
static const UT_icd mdns_queries_icd = {sizeof(struct mdns_query_entry), NULL, NULL, NULL};

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

int forward_reflector_if6(uint8_t *send_buf, size_t len, struct reflection_list *rif)
{
  struct reflection_list *el;
  struct sockaddr *dst;
  socklen_t dst_len;
  struct sockaddr_in6 sa_group6 = {
    .sin6_family=AF_INET6,
    .sin6_port = htons(MDNS_PORT),
    .sin6_addr = MDNS_ADDR6_INIT,
  };

  log_trace("mDNS forwarding to IP6 interfaces");

  dst = (struct sockaddr *) &sa_group6;
  dst_len = sizeof(sa_group6);

  dl_list_for_each(el, &(rif)->list, struct reflection_list, list) {
    if (el == rif){
      continue;
    }

    sa_group6.sin6_scope_id = el->ifindex;
    if (sendto(el->send_fd, send_buf, len, 0, dst, dst_len) == -1) {
      if (errno == EWOULDBLOCK) {
        continue;
      }
      log_err("sendto");
      return -1;
    }
  }

  return 0;
}

int forward_reflector_if4(uint8_t *send_buf, size_t len, struct reflection_list *rif)
{
  struct reflection_list *el;
  struct sockaddr *dst;
  socklen_t dst_len;

  struct sockaddr_in sa_group4 = {
    .sin_family = AF_INET,
    .sin_port = htons(MDNS_PORT),
    .sin_addr.s_addr = htonl(MDNS_ADDR4),
  };

  log_trace("mDNS forwarding to IP4 interfaces");
  dst = (struct sockaddr *) &sa_group4;
  dst_len = sizeof(sa_group4);

  dl_list_for_each(el, &(rif)->list, struct reflection_list, list) {
    if (el == rif) {
      continue;
    }

    if (sendto(el->send_fd, send_buf, len, 0, dst, dst_len) == -1) {
      if (errno == EWOULDBLOCK) {
        continue;
      }
      log_err("sendto");
      return -1;
    }
  }

  return 0;
}

void eloop_reflector_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  struct client_address peer_addr;
  uint32_t bytes_available;
  uint8_t *buf, qip[IP_ALEN];
  ssize_t num_bytes;
  size_t first = 0;
  uint16_t port;
  char peer_addr_str[INET6_ADDRSTRLEN];
  struct mdns_header header;
  char *qname = NULL;
  UT_array *answers, *queries;
  struct mdns_answer_entry *ael = NULL;
  struct mdns_query_entry *qel = NULL;
  struct reflection_list *rif = (struct reflection_list *) sock_ctx;
  struct mdns_context *context = (struct mdns_context *) eloop_ctx;

  os_memset(&peer_addr, 0, sizeof(struct client_address));

  if (ioctl(sock, FIONREAD, &bytes_available) == -1) {
    log_err("ioctl");
    return;
  }

  if ((buf = os_malloc(bytes_available)) == NULL) {
    log_err("os_malloc");
    return;
  }

  if ((num_bytes = read_domain_data(sock, (char *)buf, bytes_available, &peer_addr, 0)) == -1) {
    log_trace("read_domain_data fail");
    os_free(buf);
    return;
  }

  if (sockaddr2str((struct sockaddr_storage *)&peer_addr.addr, peer_addr_str, &port) < 0) {
    log_trace("sockaddr2str fail");
    os_free(buf);
    return;
  }

  if (peer_addr.addr.sun_family == AF_INET) {
    if(ip4_2_buf(peer_addr_str, qip) < 0) {
      log_trace("Wrong IP4 mDNS address");
      os_free(buf);
      return;      
    }
  }

  log_trace("mDNS received %u bytes from IP=%s and port=%d", num_bytes, peer_addr_str, port);
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
  utarray_new(queries, &mdns_queries_icd);

  if (decode_mdns_queries((uint8_t *) buf, (size_t) num_bytes, &first, header.nqueries, queries) < 0) {
    log_trace("decode_mdns_questions fail");
    utarray_free(queries);
    os_free(buf);
    return;
  }

  utarray_new(answers, &mdns_answers_icd);

  if (decode_mdns_answers((uint8_t *) buf, (size_t) num_bytes, &first, header.nanswers, answers) < 0) {
    log_trace("decode_mdns_questions fail");
    utarray_free(queries);
    utarray_free(answers);
    os_free(buf);
    if (qname != NULL) {
      os_free(qname);
    }
    return;
  }

  while((qel = (struct mdns_query_entry *) utarray_next(queries, qel)) != NULL) {
    if (peer_addr.addr.sun_family == AF_INET) {
      if (put_mdns_query_mapper(&context->imap, qip, qel) < 0) {
        log_trace("put_mdns_query_mapper fail");
      }
    }
  }

  while((ael = (struct mdns_answer_entry *) utarray_next(answers, ael)) != NULL) {
    if (put_mdns_answer_mapper(&context->imap, ael->ip, ael) < 0) {
      log_trace("put_mdns_answer_mapper fail");
    }
  }

  if (qname != NULL) {
    os_free(qname);
  }
  utarray_free(queries);
  utarray_free(answers);

  if (peer_addr.addr.sun_family == AF_INET6) {
    if (context->config.reflect_ip6) {
      if (forward_reflector_if6(buf, num_bytes, rif) < 0) {
        log_trace("forward_reflector_if6 fail");
        os_free(buf);
        return;
      }
    }
  } else if (peer_addr.addr.sun_family == AF_INET) {
    if (context->config.reflect_ip4) {
      if (forward_reflector_if4(buf, num_bytes, rif) < 0) {
        log_trace("forward_reflector_if4 fail");
        os_free(buf);
        return;
      }
    }
  } else {
    log_trace("unknown address type");
  }

  os_free(buf);
}

int register_reflector_if6(struct mdns_context *context)
{
  struct reflection_list *el, *rif = context->rif6;
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
    el->send_fd = create_send_mcast((struct sockaddr_storage *) &sa6, sizeof(sa6), el->ifindex);
    if (el->send_fd < 0) {
      log_trace("create_send_mcast fail for interface %s", el->ifname);
      return -1;
    }
    el->recv_fd = create_recv_mcast((struct sockaddr_storage *) &sa6, sizeof(sa6), el->ifindex);
    if (el->recv_fd < 0) {
      log_trace("create_recv_mcast fail for interface %s", el->ifname);
      return -1;
    }

    if (eloop_register_read_sock(el->recv_fd, eloop_reflector_handler, (void *) context, (void *) rif) < 0) {
      log_trace("eloop_register_read_sock fail");
      return -1;
    }

    sa_group6.sin6_scope_id = el->ifindex;
    if (join_mcast(el->recv_fd, (struct sockaddr_storage *) &sa_group6, sizeof(sa_group6), el->ifindex) < 0) {
      log_err("Failed to join interface %s to IPv6 multicast group", el->ifname);
      return -1;
    }
  }

  return 0;
}

int register_reflector_if4(struct mdns_context *context)
{
  struct reflection_list *el, *rif = context->rif4;
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
    el->send_fd = create_send_mcast((struct sockaddr_storage *) &sa4, sizeof(sa4), el->ifindex);
    if (el->send_fd < 0) {
      log_trace("create_send_mcast fail for interface %s", el->ifname);
      return -1;
    }

    el->recv_fd = create_recv_mcast((struct sockaddr_storage *) &sa4, sizeof(sa4), el->ifindex);
    if (el->recv_fd < 0) {
      log_trace("create_recv_mcast fail for interface %s", el->ifname);
      return -1;
    }

    if (eloop_register_read_sock(el->recv_fd, eloop_reflector_handler, (void *) context, (void *) rif) < 0) {
      log_trace("eloop_register_read_sock fail");
      return -1;
    }

    if (join_mcast(el->recv_fd, (struct sockaddr_storage *) &sa_group4, sizeof(sa_group4), el->ifindex) < 0) {
      log_err("Failed to join interface %s to IPv4 multicast group", el->ifname);
      return -1;
    }
  }
  
  return 0;
}

int init_reflections(hmap_vlan_conn **vlan_mapper, struct mdns_context *context)
{
  char *ifname = NULL;
  unsigned int ifindex;
  hmap_vlan_conn *current, *tmp;

  if ((context->rif4 = init_reflection_list()) == NULL) {
    log_trace("init_reflection_list fail");
    return -1;
  }

  if ((context->rif6 = init_reflection_list()) == NULL) {
    log_trace("init_reflection_list fail");
    return -1;
  }

	HASH_ITER(hh, *vlan_mapper, current, tmp) {
    ifname = current->value.ifname;

    log_trace("Adding interface %s to mDNS reflector", ifname);

    if ((ifindex = if_nametoindex(ifname)) == 0) {
      log_err("if_nametoindex");
      return -1;
    }

    if (push_reflection_list(context->rif6, ifindex, ifname) == NULL) {
      log_trace("push_reflection_list fail");
      return -1;
    }
    if (push_reflection_list(context->rif4, ifindex, ifname) == NULL) {
      log_trace("push_reflection_list fail");
      return -1;
    }
  }

  return 0;
}

int close_mdns(struct mdns_context *context)
{
  if (context != NULL) {
    if (context->rif4 != NULL) {
      close_reflector_if(context->rif4);
      free_reflection_list(context->rif4);
    }

    if (context->rif6 != NULL) {
      close_reflector_if(context->rif6);
      free_reflection_list(context->rif6);
    }
    free_mdns_mapper(&context->imap);
  }

  return 0;
}

int run_mdns(struct mdns_context *context)
{ 
  if (init_reflections(&context->vlan_mapper, context) < 0) {
    log_trace("init_reflections fail");
    return -1;
  }

  // if (register_reflector_if6(context) < 0) {
  //   log_trace("register_reflector_if6 fail");
  //   close_mdns(context->mdns_ctx);
  //   context->mdns_ctx = NULL;
  //   return -1;
  // }

  // if (register_reflector_if4(context) < 0) {
  //   log_trace("register_reflector_if4 fail");
  //   close_mdns(context->mdns_ctx);
  //   context->mdns_ctx = NULL;
  //   return -1;
  // }

  return 0;
}
