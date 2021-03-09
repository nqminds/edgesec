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
#include <netinet/icmp6.h>
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

/* Linux compat */
#ifndef IPV6_VERSION
#define IPV6_VERSION		    0x60
#define IPV6_VERSION_MASK	  0xf0
#endif /* IPV6_VERSION */

#define DNS_PORT            53
#define MDNS_PORT           5353
#define DHCP_CLIENT_PORT    68
#define DHCP_SERVER_PORT    67

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

  inaddr4_2_ip(&((cpac->ip4h)->ip_src), ip_src_str);
  inaddr4_2_ip(&((cpac->ip4h)->ip_dst), ip_dst_str);
  log_trace("IP4 ip_src=%s ip_dst=%s ip_p=%d ip_v=%d", ip_src_str, ip_dst_str, (cpac->ip4h)->ip_p, (cpac->ip4h)->ip_v);

  // Process futher packets only if IP is version 4
  return ((cpac->ip4h)->ip_v == 4);
}

bool decode_tcp_packet(struct capture_packet *cpac)
{
  if ((void *)cpac->ip4h != NULL && (void *)cpac->ip6h == NULL)
    cpac->tcph = (struct tcphdr *) ((void *)cpac->ip4h + sizeof(struct ip));
  else if ((void *)cpac->ip4h == NULL && (void *)cpac->ip6h != NULL)
    cpac->tcph = (struct tcphdr *) ((void *)cpac->ip6h + sizeof(struct ip6_hdr));
  else
    return false;

  cpac->tcph_hash = md_hash((const char*) cpac->tcph, sizeof(struct tcphdr));
  log_trace("TCP source=%d dest=%d", ntohs((cpac->tcph)->source), ntohs((cpac->tcph)->dest));
  return true;
}

bool decode_udp_packet(struct capture_packet *cpac)
{
  if ((void *)cpac->ip4h != NULL && (void *)cpac->ip6h == NULL)
    cpac->udph = (struct udphdr *) ((void *)cpac->ip4h + sizeof(struct ip));
  else if ((void *)cpac->ip4h == NULL && (void *)cpac->ip6h != NULL)
    cpac->udph = (struct udphdr *) ((void *)cpac->ip6h + sizeof(struct ip6_hdr));
  else
    return false;

  cpac->udph_hash = md_hash((const char*) cpac->udph, sizeof(struct udphdr));
  log_trace("UDP source=%d dest=%d", ntohs((cpac->udph)->source), ntohs((cpac->udph)->dest));

  return true;
}

bool decode_icmp4_packet(struct capture_packet *cpac)
{
  cpac->icmp4h = (struct icmphdr *) ((void *)cpac->ip4h + sizeof(struct ip));
  cpac->icmp4h_hash = md_hash((const char*) cpac->icmp4h, sizeof(struct icmphdr));
  log_trace("ICMP4 type=%d code=%d", (cpac->icmp4h)->type, (cpac->icmp4h)->code);

  return true;
}

bool decode_dns_packet(struct capture_packet *cpac)
{
  if ((void *)cpac->tcph != NULL && (void *)cpac->udph == NULL)
    cpac->dnsh = (struct dns_header *) ((void *)cpac->tcph + sizeof(struct tcphdr));
  else if ((void *)cpac->tcph == NULL && (void *)cpac->udph != NULL)
    cpac->dnsh = (struct dns_header *) ((void *)cpac->udph + sizeof(struct udphdr));
  else
    return false;

  cpac->dnsh_hash = md_hash((const char*) cpac->dnsh, sizeof(struct dns_header));

  log_trace("DNS");

  return true;
}

bool decode_mdns_packet(struct capture_packet *cpac)
{
  if ((void *)cpac->tcph != NULL && (void *)cpac->udph == NULL)
    cpac->mdnsh = (struct mdns_header *) ((void *)cpac->tcph + sizeof(struct tcphdr));
  else if ((void *)cpac->tcph == NULL && (void *)cpac->udph != NULL)
    cpac->mdnsh = (struct mdns_header *) ((void *)cpac->udph + sizeof(struct udphdr));
  else
    return false;

  cpac->mdnsh_hash = md_hash((const char*) cpac->mdnsh, sizeof(struct mdns_header));

  log_trace("mDNS");

  return true;
}

bool decode_dhcp_packet(struct capture_packet *cpac)
{
  log_trace("DHCP");
  return true;
}

bool decode_icmp6_packet(struct capture_packet *cpac)
{
  cpac->icmp6h = (struct icmp6_hdr *) ((void *)cpac->ip6h + sizeof(struct ip6_hdr));
  cpac->icmp6h_hash = md_hash((const char*) cpac->icmp6h, sizeof(struct icmp6_hdr));
  log_trace("ICMP6 type=%d code=%d", (cpac->icmp6h)->icmp6_type, (cpac->icmp6h)->icmp6_code);

  return true;
}

bool decode_ip6_packet(struct capture_packet *cpac)
{
  char ip_src_str[INET6_ADDRSTRLEN];
  char ip_dst_str[INET6_ADDRSTRLEN];

  // Return false if the header is not of the right length
  if (cpac->length - sizeof(struct ether_header) < sizeof(struct ip6_hdr)) {
    return false;
  }

  cpac->ip6h = (struct ip6_hdr *) ((void *)cpac->ethh + sizeof(struct ether_header));

  // Wrong IP6 version
	if (((cpac->ip6h)->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
    cpac->ip6h = NULL;
		return false;
	}

  cpac->ip6h_hash = md_hash((const char*) cpac->ip6h, sizeof(struct ip6_hdr));

  inaddr6_2_ip(&(cpac->ip6h)->ip6_src, ip_src_str);
  inaddr6_2_ip(&(cpac->ip6h)->ip6_src, ip_dst_str);

  log_trace("IP6 ip6_src=%s ip6_dst=%s ip6_un1_nxt=%d", ip_src_str, ip_dst_str,
            (cpac->ip6h)->ip6_ctlun.ip6_un1.ip6_un1_nxt);
  return true;
}

bool decode_arp_packet(struct capture_packet *cpac)
{
  cpac->arph = (struct	ether_arp*) ((void *)cpac->ethh + sizeof(struct ether_header));
  cpac->arph_hash = md_hash((const char*) cpac->arph, sizeof(struct	ether_arp));

  log_trace("ARP arp_sha=" MACSTR " arp_spa=" IPSTR " arp_tha=" MACSTR, MAC2STR((cpac->arph)->arp_sha), IP2STR((cpac->arph)->arp_spa), MAC2STR((cpac->arph)->arp_tha));

  return true;
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
    if (decode_ip6_packet(&cpac)) {
      if ((cpac.ip6h)->ip6_nxt == IPPROTO_TCP) {
        decode_tcp_packet(&cpac);
      } else if ((cpac.ip6h)->ip6_nxt == IPPROTO_UDP) {
        decode_udp_packet(&cpac);
      } else if ((cpac.ip6h)->ip6_nxt == IPPROTO_ICMPV6) {
        decode_icmp6_packet(&cpac);
      }
    }
  } else if (packet_type == ETHERTYPE_ARP) {
    decode_arp_packet(&cpac);
  }

  if ((void *)cpac.tcph != NULL) {
    if (ntohs((cpac.tcph)->source) == DNS_PORT || ntohs((cpac.tcph)->dest) == DNS_PORT) {
      decode_dns_packet(&cpac);
    } else if (ntohs((cpac.tcph)->source) == MDNS_PORT || ntohs((cpac.tcph)->dest) == MDNS_PORT) {
      decode_mdns_packet(&cpac);
    }
  } else if ((void *)cpac.udph != NULL) {
    if (ntohs((cpac.udph)->source) == DNS_PORT || ntohs((cpac.udph)->dest) == DNS_PORT) {
      decode_dns_packet(&cpac);
    } else if (ntohs((cpac.udph)->source) == MDNS_PORT || ntohs((cpac.udph)->dest) == MDNS_PORT) {
      decode_mdns_packet(&cpac);
    } else if ((ntohs((cpac.udph)->source) == DHCP_CLIENT_PORT && ntohs((cpac.udph)->dest) == DHCP_SERVER_PORT) ||
              (ntohs((cpac.udph)->source) == DHCP_SERVER_PORT && ntohs((cpac.udph)->dest) == DHCP_CLIENT_PORT)) {
      decode_dhcp_packet(&cpac);
    }
  }
  return 0;
}