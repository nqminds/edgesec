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
 * @file packet_decoder.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the packet decoder utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/if.h"
#include "../utils/hash.h"

#include "packet_decoder.h"
bool decode_ip4_packet(struct capture_packet *cpac)
{
  char ip_src_str[INET_ADDRSTRLEN];
  char ip_dst_str[INET_ADDRSTRLEN];

  // Return false if the header is not of the right length
  if (cpac->length - sizeof(struct ether_header) < sizeof(struct ip)) {
    return false;
  }

  cpac->ip4h = (struct ip *) ((void *)cpac->ethh + sizeof(struct ether_header));
  cpac->ip4h_hash = md_hash((const char*) cpac->ip4h, sizeof(struct ip));

  in_addr_2_ip(&((cpac->ip4h)->ip_src), ip_src_str);
  in_addr_2_ip(&((cpac->ip4h)->ip_dst), ip_dst_str);
  log_trace("IP4 ip_src=" IPSTR " ip_dst=" IPSTR " ip_p=%d ip_v=%d", IP2STR(ip_src_str), IP2STR(ip_dst_str), (cpac->ip4h)->ip_p, (cpac->ip4h)->ip_v);

  // Process futher packets only if IP is version 4
  return ((cpac->ip4h)->ip_v == 4);
}

void decode_tcp_packet(struct capture_packet *cpac)
{
  cpac->tcph = (struct tcphdr *) ((void *)cpac->ip4h + sizeof(struct ip));
  cpac->tcph_hash = md_hash((const char*) cpac->tcph, sizeof(struct tcphdr));
  log_trace("TCP source=%d dest=%d", ntohs((cpac->tcph)->source), ntohs((cpac->tcph)->dest));
}

void decode_udp_packet(struct capture_packet *cpac)
{
  cpac->udph = (struct udphdr *) ((void *)cpac->ip4h + sizeof(struct ip));
  cpac->udph_hash = md_hash((const char*) cpac->udph, sizeof(struct udphdr));
  log_trace("UDP source=%d dest=%d", ntohs((cpac->udph)->source), ntohs((cpac->udph)->dest));
}

void decode_icmp4_packet(struct capture_packet *cpac)
{
  log_trace("ICMP4");
}

void decode_dns_packet(struct capture_packet *cpac)
{

}

void decode_dhcp_packet(struct capture_packet *cpac)
{

}

void decode_icmp6_packet(struct capture_packet *cpac)
{
  log_trace("ICMP6");
}

void decode_ip6_packet(struct capture_packet *cpac)
{
  log_trace("IP6");
}

void decode_arp_packet(struct capture_packet *cpac)
{
  cpac->arph = (struct	ether_arp*) ((void *)cpac->ethh + sizeof(struct ether_header));
  cpac->arph_hash = md_hash((const char*) cpac->arph, sizeof(struct	ether_arp));

  log_trace("ARP arp_sha=" MACSTR " arp_spa=" IPSTR " arp_tha=" MACSTR, MAC2STR((cpac->arph)->arp_sha), IP2STR((cpac->arph)->arp_spa), MAC2STR((cpac->arph)->arp_tha));
}

int decode_packet(const struct pcap_pkthdr *header, const uint8_t *packet)
{
  struct capture_packet cpac;
  uint16_t packet_type;
  memset(&cpac, 0, sizeof(struct capture_packet));

  cpac.ethh = (struct ether_header*) packet;
  cpac.timestamp = os_get_timestamp(header->ts);
  cpac.caplen = header->caplen;
  cpac.length = header->len;
  cpac.ethh_hash = md_hash((const char*) cpac.ethh, sizeof(struct ether_header));
  packet_type = ntohs(cpac.ethh->ether_type);
    

  log_trace("Ethernet type=0x%x ether_dhost=" MACSTR " ether_shost=" MACSTR " ethh=0x%x", ntohs(cpac.ethh->ether_type), MAC2STR(cpac.ethh->ether_dhost), MAC2STR(cpac.ethh->ether_shost), cpac.ethh_hash);
  if (packet_type == ETHERTYPE_IP) {
    if (decode_ip4_packet(&cpac)) {
      if ((cpac.ip4h)->ip_p == IPPROTO_TCP) {
        decode_tcp_packet(&cpac);
      } else if ((cpac.ip4h)->ip_p == IPPROTO_UDP) {
        decode_udp_packet(&cpac);
      } else if ((cpac.ip4h)->ip_p == IPPROTO_ICMP) {
        decode_icmp4_packet(&cpac);
      }
    }
  } else if (packet_type == ETHERTYPE_IPV6) {
    decode_ip6_packet(&cpac);
  } else if (packet_type == ETHERTYPE_ARP) {
    decode_arp_packet(&cpac);
  }
  return 0;
}