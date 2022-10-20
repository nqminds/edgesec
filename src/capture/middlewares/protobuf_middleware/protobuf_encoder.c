/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the protobuf encoder utilities.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/log.h"
#include "../../../utils/allocs.h"
#include "../../../utils/os.h"

#include "../header_middleware/packet_decoder.h"

#include "eth.pb-c.h"
#include "arp.pb-c.h"
#include "ip4.pb-c.h"
#include "ip6.pb-c.h"
#include "tcp.pb-c.h"
#include "udp.pb-c.h"
#include "icmp4.pb-c.h"
#include "icmp6.pb-c.h"
#include "dns.pb-c.h"
#include "mdns.pb-c.h"
#include "dhcp.pb-c.h"

ssize_t encode_protobuf_packet(struct tuple_packet *tp, uint8_t **buffer) {
  if (tp == NULL) {
    log_error("tp param is NULL");
    return -1;
  }

  if (tp->packet == NULL) {
    log_error("tp->packet param is NULL");
    return -1;
  }

  if (buffer == NULL) {
    log_error("buffer param is NULL");
    return -1
  }

  switch (tp->type) {
    case PACKET_NONE:
      return -1;
    // case PACKET_ETHERNET:
    //   return extract_eth_statement(db, (struct eth_schema *)tp->packet);
    // case PACKET_ARP:
    //   return extract_arp_statement(db, (struct arp_schema *)tp->packet);
    // case PACKET_IP4:
    //   return extract_ip4_statement(db, (struct ip4_schema *)tp->packet);
    // case PACKET_IP6:
    //   return extract_ip6_statement(db, (struct ip6_schema *)tp->packet);
    // case PACKET_TCP:
    //   return extract_tcp_statement(db, (struct tcp_schema *)tp->packet);
    // case PACKET_UDP:
    //   return extract_udp_statement(db, (struct udp_schema *)tp->packet);
    // case PACKET_ICMP4:
    //   return extract_icmp4_statement(db, (struct icmp4_schema *)tp->packet);
    // case PACKET_ICMP6:
    //   return extract_icmp6_statement(db, (struct icmp6_schema *)tp->packet);
    // case PACKET_DNS:
    //   return extract_dns_statement(db, (struct dns_schema *)tp->packet);
    // case PACKET_MDNS:
    //   return extract_mdsn_statement(db, (struct mdns_schema *)tp->packet);
    // case PACKET_DHCP:
    //   return extract_dhcp_statement(db, (struct dhcp_schema *)tp->packet);
  }

  return -1;
}