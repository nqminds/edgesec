/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the packet decoder utilities.
 */

#ifndef PACKET_DECODER_H
#define PACKET_DECODER_H

#include <net/if.h>
#include <pcap.h>

#include <utarray.h>
#include "../../../utils/allocs.h"
#include "../../../utils/os.h"
#include "../../../utils/net.h"

#define MAX_QUESTION_LEN 255

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

struct tuple_packet {
  uint8_t *packet;   /**< Packet data */
  PACKET_TYPES type; /**< Packet type */
};

/**
 * @brief Ethernet protocol schema definition
 *
 */
struct eth_schema {
  uint64_t timestamp;           /**< Packet timestamp */
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint32_t caplen;              /**< Packet caplen */
  uint32_t length;              /**< Packet length */
  char ifname[IFNAMSIZ];        /**< Packet interface name */
  char ether_dhost[MACSTR_LEN]; /**< Packet destination eth addr */
  char ether_shost[MACSTR_LEN]; /**< Packet source ether addr */
  uint16_t ether_type;          /**< Packet packet type ID field */
};

/**
 * @brief ARP protocol schema definition
 *
 */
struct arp_schema {
  char id[MAX_RANDOM_UUID_LEN];     /**< Packet id */
  uint16_t ar_hrd;                  /**< Packet Format of hardware address.  */
  uint16_t ar_pro;                  /**< Packet Format of protocol address.  */
  uint8_t ar_hln;                   /**< Packet Length of hardware address.  */
  uint8_t ar_pln;                   /**< Packet Length of protocol address.  */
  uint16_t ar_op;                   /**< Packet ARP opcode (command).  */
  char arp_sha[MACSTR_LEN];         /**< Packet sender hardware address */
  char arp_spa[OS_INET_ADDRSTRLEN]; /**< Packet sender protocol address */
  char arp_tha[MACSTR_LEN];         /**< Packet target hardware address */
  char arp_tpa[OS_INET_ADDRSTRLEN]; /**< Packet target protocol address */
};

/**
 * @brief IP4 protocol schema definition
 *
 */
struct ip4_schema {
  char id[MAX_RANDOM_UUID_LEN];    /**< Packet id */
  char ip_src[OS_INET_ADDRSTRLEN]; /**< Packet source address */
  char ip_dst[OS_INET_ADDRSTRLEN]; /**< Packet dest address */

  uint8_t ip_hl;   /**< Packet header length */
  uint8_t ip_v;    /**< Packet version */
  uint8_t ip_tos;  /**< Packet type of service */
  uint16_t ip_len; /**< Packet total length */
  uint16_t ip_id;  /**< Packet identification */
  uint16_t ip_off; /**< Packet fragment offset field */
  uint8_t ip_ttl;  /**< Packet time to live */
  uint8_t ip_p;    /**< Packet protocol */
  uint16_t ip_sum; /**< Packet checksum */
};

/**
 * @brief IP6 protocol schema definition
 *
 */
struct ip6_schema {
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint32_t
      ip6_un1_flow; /**< Packet 4 bits version, 8 bits TC, 20 bits flow-ID */
  uint16_t ip6_un1_plen; /**< Packet payload length */
  uint8_t ip6_un1_nxt;   /**< Packet next header */
  uint8_t ip6_un1_hlim;  /**< Packet hop limit */
  uint8_t ip6_un2_vfc;   /**< Packet 4 bits version, top 4 bits tclass */
  char ip6_src[OS_INET6_ADDRSTRLEN]; /**< Packet source address */
  char ip6_dst[OS_INET6_ADDRSTRLEN]; /**< Packet destination address */
};

/**
 * @brief TCP protocol schema definition
 *
 */
struct tcp_schema {
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint16_t source;              /**< Packet source port */
  uint16_t dest;                /**< Packet destination port */
  uint32_t seq;                 /**< Packet seq flag */
  uint32_t ack_seq;             /**< Packet ack_seq flag */
  uint16_t res1;                /**< Packet res1 flag */
  uint16_t doff;                /**< Packet doff flag */
  uint16_t fin;                 /**< Packet fin flag */
  uint16_t syn;                 /**< Packet syn flag */
  uint16_t rst;                 /**< Packet rst flag */
  uint16_t psh;                 /**< Packet psh flag */
  uint16_t ack;                 /**< Packet ack flag */
  uint16_t urg;                 /**< Packet urg flag */
  uint16_t window;              /**< Packet window */
  uint16_t check_p;             /**< Packet check */
  uint16_t urg_ptr;             /**< Packet urg_ptr */
};

/**
 * @brief UDP protocol schema definition
 *
 */
struct udp_schema {
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint16_t source;              /**< Packet source port */
  uint16_t dest;                /**< Packet destination port */
  uint16_t len;                 /**< Packet udp length */
  uint16_t check_p;             /**< Packet udp checksum */
};

/**
 * @brief ICMP4 protocol schema definition
 *
 */
struct icmp4_schema {
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint8_t type;                 /**< Packet message type */
  uint8_t code;                 /**< Packet type sub-code */
  uint16_t checksum;            /**< Packet checksum */
  uint32_t gateway;             /**< Packet gateway address */
};

/**
 * @brief ICMP6 protocol schema definition
 *
 */
struct icmp6_schema {
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
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
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint16_t tid;                 /**< Packet Transaction ID */
  uint16_t flags;               /**< Packet Flags */
  uint16_t nqueries;            /**< Packet Questions */
  uint16_t nanswers;            /**< Packet Answers */
  uint16_t nauth;               /**< Packet Authority PRs */
  uint16_t nother;              /**< Packet Other PRs */
  char qname[MAX_QUESTION_LEN]; /**< Packet question name*/
};

/**
 * @brief mDNS protocol schema definition
 *
 */
struct mdns_schema {
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint16_t tid;                 /**< Packet Transaction ID */
  uint16_t flags;               /**< Packet Flags */
  uint16_t nqueries;            /**< Packet Questions */
  uint16_t nanswers;            /**< Packet Answers */
  uint16_t nauth;               /**< Packet Authority PRs */
  uint16_t nother;              /**< Packet Other PRs */
  char qname[MAX_QUESTION_LEN]; /**< Packet question name*/
};

/**
 * @brief DHCP protocol schema definition
 *
 */
struct dhcp_schema {
  char id[MAX_RANDOM_UUID_LEN]; /**< Packet id */
  uint8_t op;                   /**< Packet packet type */
  uint8_t htype; /**< Packet type of hardware address for this machine
                    (Ethernet, etc) */
  uint8_t hlen;  /**< Packet length of hardware address (of this machine) */
  uint8_t hops;  /**< Packet hops */
  uint32_t
      xid; /**< Packet random transaction id number - chosen by this machine */
  uint16_t secs;                   /**< Packet seconds used in timing */
  uint16_t flags;                  /**< Packet flags */
  char ciaddr[OS_INET_ADDRSTRLEN]; /**< Packet IP address of this machine (if we
                                      already have one) */
  char yiaddr[OS_INET_ADDRSTRLEN]; /**< Packet IP address of this machine
                                      (offered by the DHCP server) */
  char siaddr[OS_INET_ADDRSTRLEN]; /**< Packet IP address of DHCP server */
  char giaddr[OS_INET_ADDRSTRLEN]; /**< Packet IP address of DHCP relay */
  char chaddr[MACSTR_LEN];         /**< Packet client ether MAC addr */
};

/**
 * @brief DNS header definition
 *
 */
struct dns_header {
  uint16_t tid;      /**< Transaction ID */
  uint16_t flags;    /**< Flags */
  uint16_t nqueries; /**< Questions */
  uint16_t nanswers; /**< Answers */
  uint16_t nauth;    /**< Authority PRs */
  uint16_t nother;   /**< Other PRs */
};

/**
 * @brief mDNS header definition
 *
 */
struct mdns_header {
  uint16_t tid;      /**< Transaction ID */
  uint16_t flags;    /**< Flags */
  uint16_t nqueries; /**< Questions */
  uint16_t nanswers; /**< Answers */
  uint16_t nauth;    /**< Authority PRs */
  uint16_t nother;   /**< Other PRs */
};

/**
 * @brief mDNS query meta definition
 *
 */
struct mdns_query_meta {
  uint16_t qtype; /**< The type of the query, i.e. the type of RR which should
                     be returned in response */
  uint16_t uresponse : 1; /**< Boolean flag indicating whether a
                             unicast-response is desired */
  uint16_t qclass : 15;   /**< Class code, 1 a.k.a. "IN" for the Internet and IP
                             networks */
} STRUCT_PACKED;

/**
 * @brief mDNS response meta definition
 *
 */
struct mdns_answer_meta {
  uint16_t rrtype;       /**< The type of the Resource Record */
  uint16_t cflush : 1;   /**< Boolean flag indicating whether outdated cached
                            records should be purged */
  uint16_t rrclass : 15; /**< Class code, 1 a.k.a. "IN" for the Internet and IP
                            networks */
  uint32_t ttl; /**< Time interval (in seconds) that the RR should be cached */
  uint16_t rdlength; /**< Integer representing the length (in octets) of the
                        RDATA field */
} STRUCT_PACKED;

/**
 * @brief DHCP header definition (truncated)
 *
 */
struct dhcp_header {
  uint8_t op; /**< packet type */
  uint8_t
      htype; /**< type of hardware address for this machine (Ethernet, etc) */
  uint8_t hlen;    /**< length of hardware address (of this machine) */
  uint8_t hops;    /**< hops */
  uint32_t xid;    /**< random transaction id number - chosen by this machine */
  uint16_t secs;   /**< seconds used in timing */
  uint16_t flags;  /**< flags */
  uint32_t ciaddr; /**< IP address of this machine (if we already have one) */
  uint32_t
      yiaddr; /**< IP address of this machine (offered by the DHCP server) */
  uint32_t siaddr;     /**< IP address of DHCP server */
  uint32_t giaddr;     /**< IP address of DHCP relay */
  uint8_t chaddr[16];  /**< Client Hardware Address */
  uint8_t legacy[192]; /**< 192 octets of 0s. BOOTP legacy */
} STRUCT_PACKED;

/**
 * @brief Capture structure definition
 *
 */
struct capture_packet {
  struct ether_header *ethh; /**< Ethernet header.  */
  struct ether_arp *arph;    /**< Embedded ARP header.  */
  struct ip *ip4h;
  struct ip6_hdr *ip6h;
  struct tcphdr *tcph;
  struct udphdr *udph;
  struct icmp *icmp4h;
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
  char id[MAX_RANDOM_UUID_LEN];
};

/**
 * @brief Extract packets from pcap packet data
 *
 * @param ltype The link type
 * @param header The packet header as per pcap
 * @param packet The packet data
 * @param interface The packet interface
 * @param id The packet id
 * @param tp_array The array of returned packet tuples
 * @return int Total count of packet tuples
 */
int extract_packets(const char *ltype, const struct pcap_pkthdr *header,
                    const uint8_t *packet, char *interface, char *id,
                    UT_array *tp_array);

#endif
