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
#include "sync.pb-c.h"

#include "protobuf_utils.h"

ssize_t encode_eth_packet(const struct eth_schema *eths, uint8_t **buffer) {
  Eth__EthSchema eth = ETH__ETH_SCHEMA__INIT;

  eth.timestamp = eths->timestamp;
  eth.id = (char *) eths->id;
  eth.caplen = eths->caplen;
  eth.length = eths->length;
  eth.ifname = (char *) eths->ifname;
  eth.ether_dhost = (char *) eths->ether_dhost;
  eth.ether_shost = (char *) eths->ether_shost;
  eth.ether_type = eths->ether_type;

  size_t packed_size = eth__eth_schema__get_packed_size(&eth);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)eth__eth_schema__pack(&eth, *buffer);
}

ssize_t encode_arp_packet(const struct arp_schema *arps, uint8_t **buffer) {
  Arp__ArpSchema arp = ARP__ARP_SCHEMA__INIT;

  arp.id = (char *) arps->id;
  arp.ar_hrd = arps->ar_hrd;
  arp.ar_pro = arps->ar_pro;
  arp.ar_hln = arps->ar_hln;
  arp.ar_pln = arps->ar_pln;
  arp.ar_op = arps->ar_op;
  arp.arp_sha = (char *) arps->arp_sha;
  arp.arp_spa = (char *) arps->arp_spa;
  arp.arp_tha = (char *) arps->arp_tha;
  arp.arp_tpa = (char *) arps->arp_tpa;


  size_t packed_size = arp__arp_schema__get_packed_size(&arp);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)arp__arp_schema__pack(&arp, *buffer);
}

ssize_t encode_ip4_pcaket(const struct ip4_schema *ip4s, uint8_t **buffer) {
  Ip4__Ip4Schema ip4 = IP4__IP4_SCHEMA__INIT;

  ip4.id = (char *) ip4s->id;
  ip4.ip_src = (char *) ip4s->ip_src;
  ip4.ip_dst = (char *) ip4s->ip_dst;
  ip4.ip_hl = ip4s->ip_hl;
  ip4.ip_v = ip4s->ip_v;
  ip4.ip_tos = ip4s->ip_tos;
  ip4.ip_len = ip4s->ip_len;
  ip4.ip_id = ip4s->ip_id;
  ip4.ip_off = ip4s->ip_off;
  ip4.ip_ttl = ip4s->ip_ttl;
  ip4.ip_p = ip4s->ip_p;
  ip4.ip_sum = ip4s->ip_sum;

  size_t packed_size = ip4__ip4_schema__get_packed_size(&ip4);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)ip4__ip4_schema__pack(&ip4, *buffer);
}

ssize_t encode_ip6_packet(const struct ip6_schema *ip6s, uint8_t **buffer) {
  Ip6__Ip6Schema ip6 = IP6__IP6_SCHEMA__INIT;

  ip6.id = (char *) ip6s->id;
  ip6.ip6_un1_flow = ip6s->ip6_un1_flow;
  ip6.ip6_un1_plen = ip6s->ip6_un1_plen;
  ip6.ip6_un1_nxt = ip6s->ip6_un1_nxt;
  ip6.ip6_un1_hlim = ip6s->ip6_un1_hlim;
  ip6.ip6_un2_vfc = ip6s->ip6_un2_vfc;
  ip6.ip6_src = (char *) ip6s->ip6_src;
  ip6.ip6_dst = (char *) ip6s->ip6_dst;

  size_t packed_size = ip6__ip6_schema__get_packed_size(&ip6);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)ip6__ip6_schema__pack(&ip6, *buffer);
}

ssize_t encode_tcp_packet(const struct tcp_schema *tcps, uint8_t **buffer) {
  Tcp__TcpSchema tcp = TCP__TCP_SCHEMA__INIT;

  tcp.id = (char *) tcps->id;
  tcp.source = tcps->source;
  tcp.dest = tcps->dest;
  tcp.seq = tcps->seq;
  tcp.ack_seq = tcps->ack_seq;
  tcp.res1 = tcps->res1;
  tcp.doff = tcps->doff;
  tcp.fin = tcps->fin;
  tcp.syn = tcps->syn;
  tcp.rst = tcps->rst;
  tcp.psh = tcps->psh;
  tcp.ack = tcps->ack;
  tcp.urg = tcps->urg;
  tcp.window = tcps->window;
  tcp.check_p = tcps->check_p;
  tcp.urg_ptr = tcps->urg_ptr;

  size_t packed_size = tcp__tcp_schema__get_packed_size(&tcp);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)tcp__tcp_schema__pack(&tcp, *buffer);
}

ssize_t encode_udp_packet(const struct udp_schema *udps, uint8_t **buffer) {
  Udp__UdpSchema udp = UDP__UDP_SCHEMA__INIT;

  udp.id = (char *) udps->id;
  udp.source = udps->source;
  udp.dest = udps->dest;
  udp.len = udps->len;
  udp.check_p = udps->check_p;

  size_t packed_size = udp__udp_schema__get_packed_size(&udp);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)udp__udp_schema__pack(&udp, *buffer);
}

ssize_t encode_icmp4_packet(const struct icmp4_schema *icmp4s, uint8_t **buffer) {
  Icmp4__Icmp4Schema icmp4 = ICMP4__ICMP4_SCHEMA__INIT;

  icmp4.id = (char *) icmp4s->id;
  icmp4.type = icmp4s->type;
  icmp4.code = icmp4s->code;
  icmp4.checksum = icmp4s->checksum;
  icmp4.gateway = icmp4s->gateway;

  size_t packed_size = icmp4__icmp4_schema__get_packed_size(&icmp4);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)icmp4__icmp4_schema__pack(&icmp4, *buffer);
}

ssize_t encode_icmp6_packet(const struct icmp6_schema *icmp6s, uint8_t **buffer) {
  Icmp6__Icmp6Schema icmp6 = ICMP6__ICMP6_SCHEMA__INIT;

  icmp6.id = (char *) icmp6s->id;
  icmp6.icmp6_type = icmp6s->icmp6_type;
  icmp6.icmp6_code = icmp6s->icmp6_code;
  icmp6.icmp6_cksum = icmp6s->icmp6_cksum;
  icmp6.icmp6_un_data32 = icmp6s->icmp6_un_data32;

  size_t packed_size = icmp6__icmp6_schema__get_packed_size(&icmp6);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)icmp6__icmp6_schema__pack(&icmp6, *buffer);
}

ssize_t encode_dns_packet(const struct dns_schema *dnss, uint8_t **buffer) {
  Dns__DnsSchema dns = DNS__DNS_SCHEMA__INIT;

  dns.id = (char *) dnss->id;
  dns.tid = dnss->tid;
  dns.flags = dnss->flags;
  dns.nqueries = dnss->nqueries;
  dns.nanswers = dnss->nanswers;
  dns.nauth = dnss->nauth;
  dns.nother = dnss->nother;
  dns.qname = (char *) dnss->qname;

  size_t packed_size = dns__dns_schema__get_packed_size(&dns);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)dns__dns_schema__pack(&dns, *buffer);
}

ssize_t encode_mdsn_packet(const struct mdns_schema *mdnss, uint8_t **buffer) {
  Mdns__MdnsSchema mdns = MDNS__MDNS_SCHEMA__INIT;

  mdns.id = (char *) mdnss->id;
  mdns.tid = mdnss->tid;
  mdns.flags = mdnss->flags;
  mdns.nqueries = mdnss->nqueries;
  mdns.nanswers = mdnss->nanswers;
  mdns.nauth = mdnss->nauth;
  mdns.nother = mdnss->nother;
  mdns.qname = (char *) mdnss->qname;

  size_t packed_size = mdns__mdns_schema__get_packed_size(&mdns);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)mdns__mdns_schema__pack(&mdns, *buffer);
}

ssize_t encode_dhcp_packet(struct dhcp_schema *dhcps, uint8_t **buffer) {
  Dhcp__DhcpSchema dhcp = DHCP__DHCP_SCHEMA__INIT;

  dhcp.id = dhcps->id;
  dhcp.op = dhcps->op;
  dhcp.htype = dhcps->htype;
  dhcp.hlen = dhcps->hlen;
  dhcp.hops = dhcps->hops;
  dhcp.xid = dhcps->xid;
  dhcp.secs = dhcps->secs;
  dhcp.flags = dhcps->flags;
  dhcp.ciaddr = dhcps->ciaddr;
  dhcp.yiaddr = dhcps->yiaddr;
  dhcp.siaddr = dhcps->siaddr;
  dhcp.giaddr = dhcps->giaddr;
  dhcp.chaddr = dhcps->chaddr;

  size_t packed_size = dhcp__dhcp_schema__get_packed_size(&dhcp);

  if ((*buffer = os_malloc(packed_size)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)dhcp__dhcp_schema__pack(&dhcp, *buffer);
}

ssize_t encode_protobuf_packet(const struct tuple_packet *tp, uint8_t **buffer) {
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
    return -1;
  }

  *buffer = NULL;

  switch (tp->type) {
    case PACKET_NONE:
      return -1;
    case PACKET_ETHERNET:
      return encode_eth_packet((struct eth_schema *)tp->packet, buffer);
    case PACKET_ARP:
      return encode_arp_packet((struct arp_schema *)tp->packet, buffer);
    case PACKET_IP4:
      return encode_ip4_pcaket((struct ip4_schema *)tp->packet, buffer);
    case PACKET_IP6:
      return encode_ip6_packet((struct ip6_schema *)tp->packet, buffer);
    case PACKET_TCP:
      return encode_tcp_packet((struct tcp_schema *)tp->packet, buffer);
    case PACKET_UDP:
      return encode_udp_packet((struct udp_schema *)tp->packet, buffer);
    case PACKET_ICMP4:
      return encode_icmp4_packet((struct icmp4_schema *)tp->packet, buffer);
    case PACKET_ICMP6:
      return encode_icmp6_packet((struct icmp6_schema *)tp->packet, buffer);
    case PACKET_DNS:
      return encode_dns_packet((struct dns_schema *)tp->packet, buffer);
    case PACKET_MDNS:
      return encode_mdsn_packet((struct mdns_schema *)tp->packet, buffer);
    case PACKET_DHCP:
      return encode_dhcp_packet((struct dhcp_schema *)tp->packet, buffer);
  }

  return -1;
}


ssize_t encode_protobuf_sync_delimited(const PACKET_TYPES type, uint8_t *packet_buffer, size_t length, uint8_t **buffer) {
  char header_id[20] = {0};

  *buffer = NULL;

  switch (type) {
    case PACKET_NONE:
      return -1;
    case PACKET_ETHERNET:
      os_strlcpy(header_id, "eth", 20);
      break;
    case PACKET_ARP:
      os_strlcpy(header_id, "arp", 20);
      break;
    case PACKET_IP4:
      os_strlcpy(header_id, "ip4", 20);
      break;
    case PACKET_IP6:
      os_strlcpy(header_id, "ip6", 20);
      break;
    case PACKET_TCP:
      os_strlcpy(header_id, "tcp", 20);
      break;
    case PACKET_UDP:
      os_strlcpy(header_id, "udp", 20);
      break;
    case PACKET_ICMP4:
      os_strlcpy(header_id, "icmp4", 20);
      break;
    case PACKET_ICMP6:
      os_strlcpy(header_id, "icmp6", 20);
      break;
    case PACKET_DNS:
      os_strlcpy(header_id, "dns", 20);
      break;
    case PACKET_MDNS:
      os_strlcpy(header_id, "mdns", 20);
      break;
    case PACKET_DHCP:
      os_strlcpy(header_id, "dhcp", 20);
      break;
    default:
      return -1;
  }

  Tdx__VoltApi__Sync__V1__ProtobufSyncWrapper sync = TDX__VOLT_API__SYNC__V1__PROTOBUF_SYNC_WRAPPER__INIT;

  sync.header_lookup_case = TDX__VOLT_API__SYNC__V1__PROTOBUF_SYNC_WRAPPER__HEADER_LOOKUP_HEADER_ID;
  sync.header_id = header_id;
  sync.payload.len = length;
  sync.payload.data = packet_buffer;

  size_t sync_length = protobuf_c_message_del_get_packed_size((const ProtobufCMessage*)&sync);

  if ((*buffer = os_malloc(sync_length)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return protobuf_c_message_del_pack((const ProtobufCMessage*)&sync, *buffer);
}

ssize_t encode_protobuf_sync_wrapper(struct tuple_packet *tp, uint8_t **buffer) {
  uint8_t *packet_buffer = NULL;
  ssize_t packet_length = encode_protobuf_packet(tp, &packet_buffer);
  if (packet_length < 0) {
    log_error("encode_protobuf_packet fail");
    return -1;
  }

  ssize_t sync_length = encode_protobuf_sync_delimited(tp->type, packet_buffer, packet_length, buffer);
  if (sync_length < 0) {
    log_error("encode_protobuf_sync fail");
    os_free(packet_buffer);
    return -1;
  }

  os_free(packet_buffer);

  return sync_length;
}