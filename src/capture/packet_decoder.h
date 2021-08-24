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
 * @file packet_decoder.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the packet decoder utilities.
 */

#ifndef PACKET_DECODER_H
#define PACKET_DECODER_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "../utils/utarray.h"
#include "../utils/os.h"

#include "capture_config.h"

/**
 * @brief DNS header definition
 * 
 */
struct dns_header {
	uint16_t tid;		                      /**< Transaction ID */
	uint16_t flags;	                      /**< Flags */
	uint16_t nqueries;	                  /**< Questions */
	uint16_t nanswers;	                  /**< Answers */
	uint16_t nauth;		                    /**< Authority PRs */
	uint16_t nother;		                  /**< Other PRs */
};

/**
 * @brief mDNS header definition
 * 
 */
struct mdns_header {
	uint16_t tid;		                      /**< Transaction ID */
	uint16_t flags;	                      /**< Flags */
	uint16_t nqueries;	                  /**< Questions */
	uint16_t nanswers;	                  /**< Answers */
	uint16_t nauth;		                    /**< Authority PRs */
	uint16_t nother;		                  /**< Other PRs */
};

/**
 * @brief DHCP header definition (truncated)
 * 
 */
struct dhcp_header {
  uint8_t  op;                          /**< packet type */
  uint8_t  htype;                       /**< type of hardware address for this machine (Ethernet, etc) */
  uint8_t  hlen;                        /**< length of hardware address (of this machine) */
  uint8_t  hops;                        /**< hops */
  uint32_t xid;                         /**< random transaction id number - chosen by this machine */
  uint16_t secs;                        /**< seconds used in timing */
  uint16_t flags;                       /**< flags */
  struct in_addr ciaddr;                /**< IP address of this machine (if we already have one) */
  struct in_addr yiaddr;                /**< IP address of this machine (offered by the DHCP server) */
  struct in_addr siaddr;                /**< IP address of DHCP server */
  struct in_addr giaddr;                /**< IP address of DHCP relay */
};

/**
 * @brief Capture structure definition
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
  struct eth_schema eths;
  struct arp_schema arps;
  struct ip4_schema ip4s;
  struct ip6_schema ip6s;
  struct tcp_schema tcps;
  struct udp_schema udps;
  struct icmp4_schema icmp4s;
  struct icmp6_schema icmp6s;
  struct dns_schema dnss;
  struct mdns_schema mdnss;
  struct dhcp_schema dhcps;
  uint64_t timestamp;
  uint32_t caplen;
  uint32_t length;
  char ifname[IFNAMSIZ];
  char hostname[OS_HOST_NAME_MAX];
  char id[MAX_RANDOM_UUID_LEN];
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
};

/**
 * @brief Extract packets from pcap packet data
 * 
 * @param header The packet header as per pcap
 * @param packet The packet data
 * @param interface The packet interface
 * @param hostname The packet hostname
 * @param id The packet id
 * @param tp_array The array of returned packet tuples
 * @return int Total count of packet tuples
 */
int extract_packets(const struct pcap_pkthdr *header, const uint8_t *packet,
                    char *interface, char *hostname, char *id, UT_array **tp_array);

#endif
