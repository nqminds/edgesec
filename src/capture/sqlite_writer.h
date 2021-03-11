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
 * @file sqlite_writer.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the sqlite writer utilities.
 */

#ifndef SQLITE_WRITER_H
#define SQLITE_WRITER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_CREATE_TABLE "CREATE TABLE eth (i INTEGER, n numeric, t text, b blob);"
/**
 * @brief Ethernet protocol schema defintion
 * 
 */
struct eth_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  char *ether_dhost;	        /**< Packet destination eth addr */
  char *ether_shost;	        /**< Packet source ether addr */
  uint16_t ether_type;		    /**< Packet packet type ID field */
};

/**
 * @brief ARP protocol schema definition
 * 
 */
struct arp_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint16_t ar_hrd;		        /**< Packet Format of hardware address.  */
  uint16_t ar_pro;		        /**< Packet Format of protocol address.  */
  uint8_t ar_hln;		        /**< Packet Length of hardware address.  */
  uint8_t ar_pln;		        /**< Packet Length of protocol address.  */
  uint16_t ar_op;		        /**< Packet ARP opcode (command).  */
  char *arp_sha;	            /**< Packet sender hardware address */
  char *arp_spa;		        /**< Packet sender protocol address */
  char *arp_tha;	            /**< Packet target hardware address */
  char *arp_tpa;		        /**< Packet target protocol address */
};

/**
 * @brief IP4 protocol schema definition
 * 
 */
struct ip4_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint8_t ip_hl;		        /**< Packet header length */
  uint8_t ip_v;		            /**< Packet version */
  uint8_t ip_tos;			    /**< Packet type of service */
  uint16_t ip_len;		        /**< Packet total length */
  uint16_t ip_id;		        /**< Packet identification */
  uint16_t ip_off;		        /**< Packet fragment offset field */
  uint8_t ip_ttl;			    /**< Packet time to live */
  uint8_t ip_p;			        /**< Packet protocol */
  uint16_t ip_sum;		        /**< Packet checksum */
  char *ip_src;                 /**< Packet source address */
  char *ip_dst;	                /**< Packet dest address */
};

/**
 * @brief IP6 protocol schema definition
 * 
 */
struct ip6_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint32_t ip6_un1_flow;        /**< Packet 4 bits version, 8 bits TC, 20 bits flow-ID */
  uint16_t ip6_un1_plen;        /**< Packet payload length */
  uint8_t ip6_un1_nxt;          /**< Packet next header */
  uint8_t ip6_un1_hlim;         /**< Packet hop limit */
  uint8_t ip6_un2_vfc;          /**< Packet 4 bits version, top 4 bits tclass */
  char *ip6_src;                /**< Packet source address */
  char *ip6_dst;                /**< Packet destination address */
};

/**
 * @brief TCP protocol schema definition
 * 
 */
struct tcp_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint16_t source;              /**< Packet source port */
  uint16_t dest;                /**< Packet destination port */
  uint32_t seq;                 /**< Packet seq flag */
  uint32_t ack_seq;             /**< Packet ack_seq flag */
  uint8_t res1;                 /**< Packet res1 flag */
  uint8_t doff;                 /**< Packet doff flag */
  uint8_t fin;                  /**< Packet fin flag */
  uint8_t syn;                  /**< Packet syn flag */
  uint8_t rst;                  /**< Packet rst flag */
  uint8_t psh;                  /**< Packet psh flag */
  uint8_t ack;                  /**< Packet ack flag */
  uint8_t urg;                  /**< Packet urg flag */
  uint8_t ece;                  /**< Packet ece flag */
  uint8_t cwr;                  /**< Packet cwr flag */
  uint16_t window;              /**< Packet window */
  uint16_t check;               /**< Packet check */
  uint16_t urg_ptr;             /**< Packet urg_ptr */
};

/**
 * @brief UDP protocol schema definition
 * 
 */
struct udp_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint16_t source;              /**< Packet source port */
  uint16_t dest;                /**< Packet destination port */
  uint16_t len;                 /**< Packet udp length */
  uint16_t check;               /**< Packet udp checksum */
};

/**
 * @brief ICMP4 protocol schema definition
 * 
 */
struct icmp4_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint8_t type;		            /**< Packet message type */
  uint8_t code;		            /**< Packet type sub-code */
  uint16_t checksum;            /**< Packet checksum */
  uint32_t	gateway;	        /**< Packet gateway address */
};

/**
 * @brief ICMP6 protocol schema definition
 * 
 */
struct icmp6_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint8_t icmp6_type;           /**< Packet type field */
  uint8_t icmp6_code;           /**< Packet code field */
  uint16_t icmp6_cksum;         /**< Packet checksum field */
  uint32_t icmp6_un_data32;     /**< Packet type-specific field */
};

/**
 * @brief DNS protocol schema definition
 * 
 */
struct dns_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint16_t tid;		            /**< Packet Transaction ID */
  uint16_t flags;	            /**< Packet Flags */
  uint16_t nqueries;	        /**< Packet Questions */
  uint16_t nanswers;	        /**< Packet Answers */
  uint16_t nauth;		        /**< Packet Authority PRs */
  uint16_t nother;		        /**< Packet Other PRs */
};

/**
 * @brief mDNS protocol schema definition
 * 
 */
struct mdns_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint16_t tid;		            /**< Packet Transaction ID */
  uint16_t flags;	            /**< Packet Flags */
  uint16_t nqueries;	        /**< Packet Questions */
  uint16_t nanswers;	        /**< Packet Answers */
  uint16_t nauth;		        /**< Packet Authority PRs */
  uint16_t nother;		        /**< Packet Other PRs */
};

/**
 * @brief DHCP protocol schema definition
 * 
 */
struct dhcp_schema {
  uint32_t hash;                /**< Packet hash */
  uint64_t timestamp;           /**< Packet timestamp */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  uint8_t  op;                  /**< Packet packet type */
  uint8_t  htype;               /**< Packet type of hardware address for this machine (Ethernet, etc) */
  uint8_t  hlen;                /**< Packet length of hardware address (of this machine) */
  uint8_t  hops;                /**< Packet hops */
  uint32_t xid;                 /**< Packet random transaction id number - chosen by this machine */
  uint16_t secs;                /**< Packet seconds used in timing */
  uint16_t flags;               /**< Packet flags */
  char *ciaddr;                 /**< Packet IP address of this machine (if we already have one) */
  char *yiaddr;                 /**< Packet IP address of this machine (offered by the DHCP server) */
  char *siaddr;                 /**< Packet IP address of DHCP server */
  char *giaddr;                 /**< Packet IP address of DHCP relay */
};

#endif
