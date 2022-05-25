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
 * @file capture_config.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the capture config structures.
 *
 * Defines the function to generate the config parameters for the capture
 * service. It also defines all the metadata and database schema for the
 * captured packets.
 */

#ifndef CAPTURE_CONFIG_H
#define CAPTURE_CONFIG_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <stdbool.h>

#include "../utils/allocs.h"
#include "../utils/os.h"

#define PCAP_DB_NAME                                                           \
  "pcap-meta" SQLITE_EXTENSION /* sqlite db name for raw pcap data */
#define PCAP_SUBFOLDER_NAME                                                    \
  "./pcap" /* Subfodler name to store raw pcap data                            \
            */

#define MAX_ANALYSER_NAME_SIZE                                                 \
  64 /* Maximum length of the packet analyser name */
#define MAX_FILTER_SIZE                                                        \
  4094 /* Maximum length of the filter string for libpcap */

#define PACKET_ANALYSER_DEFAULT "default"
#define PACKET_ANALYSER_NDPI "ndpi"

#define DEFAULT_CAPTURE_TIMEOUT                                                \
  10 /* Default capture timeout for in milliseconds */
#define DEFAULT_CAPTURE_INTERVAL                                               \
  10 /* Default capture interval for in milliseconds */

// #define META_HASH_SIZE              SHA256_HASH_LEN * 2 + 1
#define MAX_PROTOCOL_NAME_LEN                                                  \
  64 /* Maximum length of the captured network protocol name */
#define MAX_FINGERPRINT_LEN 1024
#define MAX_QUERY_LEN MAX_OS_PATH_LEN

#define CAPTURE_MAX_OPT 26

#define CAPTURE_OPT_STRING ":c:i:q:f:t:n:p:y:x:z:r:b:dvhmewu" // gjlkoas
#define CAPTURE_USAGE_STRING                                                   \
  "\t%s [-c config] [-d] [-h] [-v] [(-y engine [-w] [-u]) | (-b size)] [-i "   \
  "interface] [-q domain]"                                                     \
  "[-f filter] [-m] [-t timeout] [-n interval] "                               \
  "[-e] [-r params]\n"
extern const char *const capture_description_string;

#define CAPTURE_OPT_DEFS                                                       \
  "\t-c config\t Path to the config file name\n"                               \
  "\t-q domain\t The UNIX domain path\n"                                       \
  "\t-x command\t The UNIX domain command\n"                                   \
  "\t-z delimiter\t The UNIX domain command delimiter\n"                       \
  "\t-i interface\t The capture interface name\n"                              \
  "\t-f filter\t The capture filter expression\n"                              \
  "\t-t timeout\t The buffer timeout (milliseconds)\n"                         \
  "\t-n interval\t The process interval (milliseconds)\n"                      \
  "\t-y analyser\t Analyser\n"                                                 \
  "\t-p path\t\t The db path\n"                                                \
  "\t-m\t\t Promiscuous mode\n"                                                \
  "\t-e\t\t Immediate mode\n"                                                  \
  "\t-u\t\t Write to file\n"                                                   \
  "\t-w\t\t Write to db\n"                                                     \
  "\t-r\t\t Sync store size and send size (val1,val2)\n"                       \
  "\t-b size\t\t Maximum capture store size before cleanup (in KiB)\n"         \
  "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n"               \
  "\t-h\t\t Show help\n"                                                       \
  "\t-v\t\t Show app version\n\n"

#define MAX_SCHEMA_STR_LENGTH 100

#define MAX_QUESTION_LEN 255

#define MAX_CAPIF_LIST_SIZE 4095
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
 * @brief The capture configuration structure
 *
 */
struct capture_conf {
  char capture_bin_path[MAX_OS_PATH_LEN]; /**< The capture binary path string */
  char domain_server_path[MAX_OS_PATH_LEN]; /**< Specifies the path to the UNIX
                                               domain socket server */
  char domain_command[MAX_SUPERVISOR_CMD_SIZE]; /**< Specifies the UNIX domain
                                                   command */
  char domain_delim; /**< Specifies the UNIX domain command delimiter */
  char capture_interface[MAX_CAPIF_LIST_SIZE]; /**< The capture interface
                                                  name(s) (if multiple delimited
                                                  by space) */
  bool promiscuous; /**< Specifies whether the interface is to be put into
                       promiscuous mode. If promiscuous param is non-zero,
                       promiscuous mode will be set, otherwise it will not be
                       set */
  bool immediate;   /**< Sets whether immediate mode should be set on a capture
                       handle when the handle is activated. If immediate param is
                       non-zero, immediate mode will be set, otherwise it will not
                       be set. */
  uint32_t
      buffer_timeout;        /**< Specifies the packet buffer timeout, as a
                                non-negative value, in milliseconds. (See pcap(3PCAP)
                                for an explanation of the packet buffer timeout.) */
  uint32_t process_interval; /**< Specifies the packet process interval, in
                                milliseconds. */
  char analyser[MAX_ANALYSER_NAME_SIZE]; /**< Specifies the packet analyser
                                            engine. */
  bool file_write; /**< Specifies wether the packets should be saved to file(s).
                    */
  bool db_write;   /**< Specifies wether the packets should be saved in a sqlite
                      db. */
  char db_path[MAX_OS_PATH_LEN]; /**< Specifies the path to the sqlite3 dbs */
  char filter[MAX_FILTER_SIZE]; /**< Specifies the filter expression or pcap lib
                                 */
  ssize_t sync_store_size;      /**< Specifies the sync store size */
  ssize_t sync_send_size;       /**< Specifies the sync send size */
  uint32_t capture_store_size;  /**< Specifies the capture store size in KiB */
};

struct tuple_packet {
  uint8_t *packet;   /**< Packet data */
  PACKET_TYPES type; /**< Packet type */
};

/**
 * @brief Ethernet protocol schema definition
 *
 */
struct eth_schema {
  uint64_t timestamp;              /**< Packet timestamp */
  char id[MAX_RANDOM_UUID_LEN];    /**< Packet id */
  uint32_t caplen;                 /**< Packet caplen */
  uint32_t length;                 /**< Packet length */
  char ifname[IFNAMSIZ];           /**< Packet interface name */
  char hostname[OS_HOST_NAME_MAX]; /**< Packet hostname name */
  char ether_dhost[MACSTR_LEN];    /**< Packet destination eth addr */
  char ether_shost[MACSTR_LEN];    /**< Packet source ether addr */
  uint16_t ether_type;             /**< Packet packet type ID field */
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
};

struct alert_meta {
  uint64_t timestamp;                    /**< Alert timestamp */
  char analyser[MAX_ANALYSER_NAME_SIZE]; /**< Alert analyser type */
  char hostname[OS_HOST_NAME_MAX];       /**< Alert hostname */
  char ifname[IFNAMSIZ];                 /**< Alert monitoring interface */
  uint8_t src_mac_addr[ETH_ALEN];        /**< Source MAC address */
  uint8_t dst_mac_addr[ETH_ALEN];        /**< Destination MAC address */
  uint8_t risk;                          /**< Alert risk value */
};

/**
 * @brief Translate a capture process option to a config structure value
 *
 * @param key Capture process option key
 * @param opt Capture process option value
 * @param config The config structure
 * @return int 0 on success, -1 on error and 1 for an unknown option key
 */
int capture_opt2config(char key, char *value, struct capture_conf *config);

/**
 * @brief Transforms a config structure to opt string array
 *
 * @param config The config structure
 * @return char** the opt string array, NULL on failure
 */

char **capture_config2opt(struct capture_conf *config);
/**
 * @brief Free opt string array
 *
 * @param opt_str Opt string array
 */
void capture_freeopt(char **opt_str);

#endif
