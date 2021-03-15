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
#include "../utils/utarray.h"

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

#define MAX_PACKET_TYPES    10

/**
 * @brief Capturee structure definition
 * 
 */
struct capture_packet {
  struct ether_header *ethh;           /**< Ethernet header.  */
  struct ether_arp *arph;              /**< Embedded ARP header.  */
  struct ip *ip4h;
  struct ip6_hdr *ip6h;
  struct tcphdr *tcph;
  struct udphdr *udph;
  struct icmphdr *icmp4h;
  struct icmp6_hdr *icmp6h;
  struct dns_header *dnsh;
  struct mdns_header *mdnsh;
  struct dhcp_header *dhcph;
  uint64_t timestamp;
  uint32_t caplen;
  uint32_t length;
  uint32_t ethh_hash;
  uint32_t arph_hash;
  uint32_t ip4h_hash;
  uint32_t ip6h_hash;
  uint32_t tcph_hash;
  uint32_t udph_hash;
  uint32_t icmp4h_hash;
  uint32_t icmp6h_hash;
  uint32_t dnsh_hash;
  uint32_t mdnsh_hash;
  uint32_t dhcph_hash;
  int count;
};

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL, NULL};

bool decode_ip4_packet(struct capture_packet *cpac)
{
  // char ip_src_str[INET_ADDRSTRLEN];
  // char ip_dst_str[INET_ADDRSTRLEN];

  // Return false if the header is not of the right length
  if (cpac->length - sizeof(struct ether_header) < sizeof(struct ip)) {
    return false;
  }

  cpac->ip4h = (struct ip *) ((void *)cpac->ethh + sizeof(struct ether_header));
  cpac->ip4h_hash = md_hash((const char*) cpac->ip4h, sizeof(struct ip));

  // inaddr4_2_ip(&((cpac->ip4h)->ip_src), ip_src_str);
  // inaddr4_2_ip(&((cpac->ip4h)->ip_dst), ip_dst_str);
  // log_trace("IP4 ip_src=%s ip_dst=%s ip_p=%d ip_v=%d", ip_src_str, ip_dst_str, (cpac->ip4h)->ip_p, (cpac->ip4h)->ip_v);

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
  // log_trace("TCP source=%d dest=%d", ntohs((cpac->tcph)->source), ntohs((cpac->tcph)->dest));
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
  // log_trace("UDP source=%d dest=%d", ntohs((cpac->udph)->source), ntohs((cpac->udph)->dest));

  return true;
}

bool decode_icmp4_packet(struct capture_packet *cpac)
{
  cpac->icmp4h = (struct icmphdr *) ((void *)cpac->ip4h + sizeof(struct ip));
  cpac->icmp4h_hash = md_hash((const char*) cpac->icmp4h, sizeof(struct icmphdr));
  // log_trace("ICMP4 type=%d code=%d", (cpac->icmp4h)->type, (cpac->icmp4h)->code);

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

  // log_trace("DNS");

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

  // log_trace("mDNS");

  return true;
}

bool decode_dhcp_packet(struct capture_packet *cpac)
{
  // log_trace("DHCP");
  return false;
}

bool decode_icmp6_packet(struct capture_packet *cpac)
{
  cpac->icmp6h = (struct icmp6_hdr *) ((void *)cpac->ip6h + sizeof(struct ip6_hdr));
  cpac->icmp6h_hash = md_hash((const char*) cpac->icmp6h, sizeof(struct icmp6_hdr));
  // log_trace("ICMP6 type=%d code=%d", (cpac->icmp6h)->icmp6_type, (cpac->icmp6h)->icmp6_code);

  return true;
}

bool decode_ip6_packet(struct capture_packet *cpac)
{
  // char ip_src_str[INET6_ADDRSTRLEN];
  // char ip_dst_str[INET6_ADDRSTRLEN];

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

  // inaddr6_2_ip(&(cpac->ip6h)->ip6_src, ip_src_str);
  // inaddr6_2_ip(&(cpac->ip6h)->ip6_dst, ip_dst_str);

  // log_trace("IP6 ip6_src=%s ip6_dst=%s ip6_un1_nxt=%d", ip_src_str, ip_dst_str,
  //           (cpac->ip6h)->ip6_ctlun.ip6_un1.ip6_un1_nxt);
  return true;
}

bool decode_arp_packet(struct capture_packet *cpac)
{
  cpac->arph = (struct	ether_arp*) ((void *)cpac->ethh + sizeof(struct ether_header));
  cpac->arph_hash = md_hash((const char*) cpac->arph, sizeof(struct	ether_arp));

  // log_trace("ARP arp_sha=" MACSTR " arp_spa=" IPSTR " arp_tha=" MACSTR, MAC2STR((cpac->arph)->arp_sha), IP2STR((cpac->arph)->arp_spa), MAC2STR((cpac->arph)->arp_tha));

  return true;
}

struct capture_packet decode_packet(const struct pcap_pkthdr *header, const uint8_t *packet)
{
  struct capture_packet cpac;
  uint16_t packet_type;
  memset(&cpac, 0, sizeof(struct capture_packet));

  cpac.ethh = (struct ether_header*) packet;
  cpac.timestamp = os_get_timestamp(header->ts);
  cpac.caplen = header->caplen;
  cpac.length = header->len;
  cpac.ethh_hash = md_hash((const char*) cpac.ethh, sizeof(struct ether_header));
  cpac.count = 1;
  packet_type = ntohs(cpac.ethh->ether_type);
    
  // log_trace("Ethernet type=0x%x ether_dhost=" MACSTR " ether_shost=" MACSTR " ethh=0x%x", ntohs(cpac.ethh->ether_type), MAC2STR(cpac.ethh->ether_dhost), MAC2STR(cpac.ethh->ether_shost), cpac.ethh_hash);
  if (packet_type == ETHERTYPE_IP) {
    if (decode_ip4_packet(&cpac)) {
      cpac.count ++;
      if ((cpac.ip4h)->ip_p == IPPROTO_TCP) {
        if (decode_tcp_packet(&cpac)) cpac.count ++;
      } else if ((cpac.ip4h)->ip_p == IPPROTO_UDP) {
        if(decode_udp_packet(&cpac)) cpac.count ++;
      } else if ((cpac.ip4h)->ip_p == IPPROTO_ICMP) {
        if(decode_icmp4_packet(&cpac)) cpac.count ++;
      }
    }
  } else if (packet_type == ETHERTYPE_IPV6) {
    if (decode_ip6_packet(&cpac)) {
      cpac.count ++;
      if ((cpac.ip6h)->ip6_nxt == IPPROTO_TCP) {
        if(decode_tcp_packet(&cpac)) cpac.count ++;
      } else if ((cpac.ip6h)->ip6_nxt == IPPROTO_UDP) {
        if(decode_udp_packet(&cpac)) cpac.count ++;
      } else if ((cpac.ip6h)->ip6_nxt == IPPROTO_ICMPV6) {
        if(decode_icmp6_packet(&cpac)) cpac.count ++;
      }
    }
  } else if (packet_type == ETHERTYPE_ARP) {
    if(decode_arp_packet(&cpac)) cpac.count ++;
  }

  if ((void *)cpac.tcph != NULL) {
    if (ntohs((cpac.tcph)->source) == DNS_PORT || ntohs((cpac.tcph)->dest) == DNS_PORT) {
      if(decode_dns_packet(&cpac)) cpac.count ++;
    } else if (ntohs((cpac.tcph)->source) == MDNS_PORT || ntohs((cpac.tcph)->dest) == MDNS_PORT) {
      if(decode_mdns_packet(&cpac)) cpac.count ++;
    }
  } else if ((void *)cpac.udph != NULL) {
    if (ntohs((cpac.udph)->source) == DNS_PORT || ntohs((cpac.udph)->dest) == DNS_PORT) {
      if(decode_dns_packet(&cpac)) cpac.count ++;
    } else if (ntohs((cpac.udph)->source) == MDNS_PORT || ntohs((cpac.udph)->dest) == MDNS_PORT) {
      if(decode_mdns_packet(&cpac)) cpac.count ++;
    } else if ((ntohs((cpac.udph)->source) == DHCP_CLIENT_PORT && ntohs((cpac.udph)->dest) == DHCP_SERVER_PORT) ||
              (ntohs((cpac.udph)->source) == DHCP_SERVER_PORT && ntohs((cpac.udph)->dest) == DHCP_CLIENT_PORT)) {
      if(decode_dhcp_packet(&cpac)) cpac.count ++;
    }
  }
  return cpac;
}

void free_packet_tuple(struct tuple_packet *tp)
{
  if (tp) {
    if (tp->packet)
      os_free(tp->packet);
  }
}

int extract_packets(const struct pcap_pkthdr *header, const uint8_t *packet, UT_array **tp_array)
{
  struct capture_packet cpac;
  struct tuple_packet tp;
  utarray_new(*tp_array, &tp_list_icd);

  if (header->caplen >= sizeof(struct ether_header)) {
    cpac = decode_packet(header, packet);
    if (cpac.count) {
      tp.mp.caplen = cpac.caplen;
      tp.mp.length = cpac.length;
      tp.mp.timestamp = cpac.timestamp;
      tp.mp.ethh_hash = cpac.ethh_hash;

      if (cpac.ethh != NULL) {
        tp.packet = os_malloc(sizeof(struct ether_header));
        os_memcpy(tp.packet, cpac.ethh, sizeof(struct ether_header));
        tp.mp.hash = cpac.ethh_hash;
        tp.mp.type = PACKET_ETHERNET;
        utarray_push_back(*tp_array, &tp);
      }

      if (cpac.arph != NULL) {
        tp.packet = os_malloc(sizeof(struct ether_arp));
        os_memcpy(tp.packet, cpac.arph, sizeof(struct ether_arp));
        tp.mp.hash = cpac.arph_hash;
        tp.mp.type = PACKET_ARP;
        utarray_push_back(*tp_array, &tp);
      }

      if (cpac.ip4h != NULL) {
        tp.packet = os_malloc(sizeof(struct ip));
        os_memcpy(tp.packet, cpac.ip4h, sizeof(struct ip));
        tp.mp.hash = cpac.ip4h_hash;
        tp.mp.type = PACKET_IP4;
        utarray_push_back(*tp_array, &tp);
      };

      if (cpac.ip6h != NULL) {
        tp.packet = os_malloc(sizeof(struct ip6_hdr));
        os_memcpy(tp.packet, cpac.ip6h, sizeof(struct ip6_hdr));
        tp.mp.hash = cpac.ip6h_hash;
        tp.mp.type = PACKET_IP6;
        utarray_push_back(*tp_array, &tp);
      };

      if (cpac.tcph != NULL) {
        tp.packet = os_malloc(sizeof(struct tcphdr));
        os_memcpy(tp.packet, cpac.tcph, sizeof(struct tcphdr));
        tp.mp.hash = cpac.tcph_hash;
        tp.mp.type = PACKET_TCP;
        utarray_push_back(*tp_array, &tp);
      };

      if (cpac.udph != NULL) {
        tp.packet = os_malloc(sizeof(struct udphdr));
        os_memcpy(tp.packet, cpac.udph, sizeof(struct udphdr));
        tp.mp.hash = cpac.udph_hash;
        tp.mp.type = PACKET_UDP;
        utarray_push_back(*tp_array, &tp);
      };

      if (cpac.icmp4h != NULL) {
        tp.packet = os_malloc(sizeof(struct icmphdr));
        os_memcpy(tp.packet, cpac.icmp4h, sizeof(struct icmphdr));
        tp.mp.hash = cpac.icmp4h_hash;
        tp.mp.type = PACKET_ICMP4;
        utarray_push_back(*tp_array, &tp);
      };

      if (cpac.icmp6h != NULL) {
        tp.packet = os_malloc(sizeof(struct icmp6_hdr));
        os_memcpy(tp.packet, cpac.icmp6h, sizeof(struct icmp6_hdr));
        tp.mp.hash = cpac.icmp6h_hash;
        tp.mp.type = PACKET_ICMP6;
        utarray_push_back(*tp_array, &tp);
      };

      if (cpac.dnsh != NULL) {
        tp.packet = os_malloc(sizeof(struct dns_header));
        os_memcpy(tp.packet, cpac.dnsh, sizeof(struct dns_header));
        tp.mp.hash = cpac.dnsh_hash;
        tp.mp.type = PACKET_DNS;
        utarray_push_back(*tp_array, &tp);
      };
      if (cpac.mdnsh != NULL) {
        tp.packet = os_malloc(sizeof(struct mdns_header));
        os_memcpy(tp.packet, cpac.mdnsh, sizeof(struct mdns_header));
        tp.mp.hash = cpac.mdnsh_hash;
        tp.mp.type = PACKET_MDNS;
        utarray_push_back(*tp_array, &tp);
      };
      if (cpac.dhcph != NULL) {
        tp.packet = os_malloc(sizeof(struct dhcp_header));
        os_memcpy(tp.packet, cpac.dhcph, sizeof(struct dhcp_header));
        tp.mp.hash = cpac.dhcph_hash;
        tp.mp.type = PACKET_DHCP;
        utarray_push_back(*tp_array, &tp);
      };
    }
  }

  return utarray_len(*tp_array);
}