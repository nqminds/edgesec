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

typedef enum packet_types {
  PACKET_NONE = 0,
  PACKET_ETHERNET,
  PACKET_ARP,
  PACKET_IP4,
  PACKET_IP6,
  PACKET_TCP,
  PACKET_UDP,
  PACKET_ICMP4,
  PACKET_ICMP6,
  PACKET_DNS,
  PACKET_MDNS,
  PACKET_DHCP
} PACKET_TYPES;

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
 * @brief Meta packet structure definition
 * 
 */
struct meta_packet {
  PACKET_TYPES type;            /**< Packet type */
  uint32_t hash;                /**< Packet header hash */
  uint32_t ethh_hash;           /**< Packet ethernet header hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
};

struct tuple_packet {
  uint8_t *packet;                  /**< Packet data */
  struct meta_packet mp;            /**< Packet metadata */
};

/**
 * @brief Extract packets from pcap packet data
 * 
 * @param header The packet header as per pcap
 * @param packet The packet data
 * @param tp_array The array of returned packet tuples
 * @return int Total count of packet tuples
 */
int extract_packets(const struct pcap_pkthdr *header, const uint8_t *packet, UT_array **tp_array);

/**
 * @brief Frees an allocated packet tuple
 * 
 * @param tp The pointer to the packet tuple
 */
void free_packet_tuple(struct tuple_packet *tp);
#endif
