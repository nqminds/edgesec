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

#include <stdint.h>
#include <sqlite3.h>

#include "packet_decoder.h"

#include "../utils/os.h"
#include "../utils/squeue.h"

#define MAX_DB_NAME           100

#define MAX_SCHEMA_STR_LENGTH 100
#define ETH_CREATE_TABLE "CREATE TABLE eth (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, "\
                         "caplen INTEGER, length INTEGER, " \
                         "ether_dhost TEXT, ether_shost TEXT, ether_type INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define ARP_CREATE_TABLE "CREATE TABLE arp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, "\
                         "caplen INTEGER, length INTEGER, " \
                         "arp_hrd INTEGER, arp_pro INTEGER, arp_hln INTEGER, " \
                         "arp_pln INTEGER, arp_op INTEGER, arp_sha TEXT, arp_spa TEXT, " \
                         "arp_tha TEXT, arp_tpa TEXT, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define IP4_CREATE_TABLE "CREATE TABLE ip4 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                         "caplen INTEGER, length INTEGER, " \
                         "ip_hl INTEGER, ip_v INTEGER, ip_tos INTEGER, ip_len INTEGER, ip_id INTEGER, " \
                         "ip_off INTEGER, ip_ttl INTEGER, ip_p INTEGER, ip_sum INTEGER, ip_src TEXT, " \
                         "ip_dst TEXT, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define IP6_CREATE_TABLE "CREATE TABLE ip6 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                         "caplen INTEGER, length INTEGER, " \
                         "ip6_un1_flow INTEGER, ip6_un1_plen INTEGER, ip6_un1_nxt INTEGER, cip6_un1_hlim INTEGER, " \
                         "ip6_un2_vfc INTEGER, ip6_src TEXT, ip6_dst TEXT, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define TCP_CREATE_TABLE "CREATE TABLE tcp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                         "caplen INTEGER, length INTEGER, " \
                         "source INTEGER, dest INTEGER, seq INTEGER, ack_seq INTEGER, res1 INTEGER, doff INTEGER, fin INTEGER, " \
                         "syn INTEGER, rst INTEGER, psh INTEGER, ack INTEGER, urg INTEGER, window INTEGER, check_p INTEGER, " \
                         "urg_ptr INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define UDP_CREATE_TABLE "CREATE TABLE udp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                         "caplen INTEGER, length INTEGER, " \
                         "source INTEGER, dest INTEGER, len INTEGER, check_p INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define ICMP4_CREATE_TABLE "CREATE TABLE icmp4 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                           "caplen INTEGER, length INTEGER, " \
                           "type INTEGER, code INTEGER, checksum INTEGER, gateway INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define ICMP6_CREATE_TABLE "CREATE TABLE icmp6 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                           "caplen INTEGER, length INTEGER, " \
                           "icmp6_type INTEGER, icmp6_code INTEGER, icmp6_cksum INTEGER, icmp6_un_data32 INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define DNS_CREATE_TABLE "CREATE TABLE dns (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                         "caplen INTEGER, length INTEGER, " \
                         "tid INTEGER, flags INTEGER, nqueries INTEGER, nanswers INTEGER, nauth INTEGER, " \
                         "nother INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define MDNS_CREATE_TABLE "CREATE TABLE mdns (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                          "caplen INTEGER, length INTEGER, " \
                          "tid INTEGER, flags INTEGER, nqueries INTEGER, nanswers INTEGER, nauth INTEGER, " \
                          "nother INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define DHCP_CREATE_TABLE "CREATE TABLE dhcp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, " \
                          "caplen INTEGER, length INTEGER, " \
                          "op INTEGER, htype INTEGER, hlen INTEGER, hops INTEGER, xid INTEGER, secs INTEGER, flags INTEGER, " \
                          "ciaddr TEXT, yiaddr TEXT, siaddr TEXT, giaddr TEXT, PRIMARY KEY (hash, timestamp, ethh_hash));"

#define ETH_INSERT_INTO "INSERT INTO eth VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, @ether_dhost, @ether_shost, @ether_type);"
#define ARP_INSERT_INTO "INSERT INTO arp VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                        "@arp_hrd, @arp_pro, @arp_hln, @arp_pln, @arp_op, @arp_sha, @arp_spa, " \
                        "@arp_tha, @arp_tpa);"
#define IP4_INSERT_INTO "INSERT INTO ip4 VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, @ip_hl, @ip_v, @ip_tos, @ip_len, @ip_id, " \
                        "@ip_off, @ip_ttl, @ip_p, @ip_sum, @ip_src, @ip_dst);"
#define IP6_INSERT_INTO "INSERT INTO ip6 VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                        "@ip6_un1_flow, @ip6_un1_plen, @ip6_un1_nxt, @cip6_un1_hlim, @ip6_un2_vfc, @ip6_src, @ip6_dst);"
#define TCP_INSERT_INTO "INSERT INTO tcp VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                        "@source, @dest, @seq, @ack_seq, @res1, @doff, @fin, " \
                        "@syn, @rst, @psh, @ack, @urg, @window, @check_p, @urg_ptr);"
#define UDP_INSERT_INTO "INSERT INTO udp VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                        "@source, @dest, @len, @check_p);"
#define ICMP4_INSERT_INTO "INSERT INTO icmp4 VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                          "@type, @code, @checksum, @gateway);"
#define ICMP6_INSERT_INTO "INSERT INTO icmp6 VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                          "@icmp6_type, @icmp6_code, @icmp6_cksum, @icmp6_un_data32);"
#define DNS_INSERT_INTO "INSERT INTO dns VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                        "@tid, @flags, @nqueries, @nanswers, @nauth, @nother);"
#define MDNS_INSERT_INTO "INSERT INTO mdns VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                         "@tid, @flags, @nqueries, @nanswers, @nauth, @nother);"
#define DHCP_INSERT_INTO "INSERT INTO dhcp VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, " \
                          "@op, @htype, @hlen, @hops, @xid, @secs, @flags, " \
                          "@ciaddr, @yiaddr, @siaddr, @giaddr);"

/**
 * @brief Ethernet protocol schema defintion
 * 
 */
struct eth_schema {
  uint32_t hash;                                    /**< Packet hash */
  uint64_t timestamp;                               /**< Packet timestamp */
  uint32_t caplen;                                  /**< Packet caplen */
  uint32_t length;                                  /**< Packet length */
  char ether_dhost[MAX_SCHEMA_STR_LENGTH];	        /**< Packet destination eth addr */
  char ether_shost[MAX_SCHEMA_STR_LENGTH];	        /**< Packet source ether addr */
  uint16_t ether_type;		                          /**< Packet packet type ID field */
};

/**
 * @brief ARP protocol schema definition
 * 
 */
struct arp_schema {
  uint32_t hash;                                    /**< Packet hash */
  uint64_t timestamp;                               /**< Packet timestamp */
  uint32_t caplen;                                  /**< Packet caplen */
  uint32_t length;                                  /**< Packet length */
  uint16_t ar_hrd;		                              /**< Packet Format of hardware address.  */
  uint16_t ar_pro;		                              /**< Packet Format of protocol address.  */
  uint8_t ar_hln;		                                /**< Packet Length of hardware address.  */
  uint8_t ar_pln;		                                /**< Packet Length of protocol address.  */
  uint16_t ar_op;		                                /**< Packet ARP opcode (command).  */
  char arp_sha[MAX_SCHEMA_STR_LENGTH];	            /**< Packet sender hardware address */
  char arp_spa[MAX_SCHEMA_STR_LENGTH];		          /**< Packet sender protocol address */
  char arp_tha[MAX_SCHEMA_STR_LENGTH];	            /**< Packet target hardware address */
  char arp_tpa[MAX_SCHEMA_STR_LENGTH];		          /**< Packet target protocol address */
};

/**
 * @brief IP4 protocol schema definition
 * 
 */
struct ip4_schema {
  uint32_t hash;                                      /**< Packet hash */
  uint64_t timestamp;                                 /**< Packet timestamp */
  uint32_t caplen;                                    /**< Packet caplen */
  uint32_t length;                                    /**< Packet length */
  uint8_t ip_hl;		                                  /**< Packet header length */
  uint8_t ip_v;		                                    /**< Packet version */
  uint8_t ip_tos;			                                /**< Packet type of service */
  uint16_t ip_len;		                                /**< Packet total length */
  uint16_t ip_id;		                                  /**< Packet identification */
  uint16_t ip_off;		                                /**< Packet fragment offset field */
  uint8_t ip_ttl;			                                /**< Packet time to live */
  uint8_t ip_p;			                                  /**< Packet protocol */
  uint16_t ip_sum;		                                /**< Packet checksum */
  char ip_src[MAX_SCHEMA_STR_LENGTH];                 /**< Packet source address */
  char ip_dst[MAX_SCHEMA_STR_LENGTH];	                /**< Packet dest address */
};

/**
 * @brief IP6 protocol schema definition
 * 
 */
struct ip6_schema {
  uint32_t hash;                                      /**< Packet hash */
  uint64_t timestamp;                                 /**< Packet timestamp */
  uint32_t caplen;                                    /**< Packet caplen */
  uint32_t length;                                    /**< Packet length */
  uint32_t ip6_un1_flow;                              /**< Packet 4 bits version, 8 bits TC, 20 bits flow-ID */
  uint16_t ip6_un1_plen;                              /**< Packet payload length */
  uint8_t ip6_un1_nxt;                                /**< Packet next header */
  uint8_t ip6_un1_hlim;                               /**< Packet hop limit */
  uint8_t ip6_un2_vfc;                                /**< Packet 4 bits version, top 4 bits tclass */
  char ip6_src[MAX_SCHEMA_STR_LENGTH];                /**< Packet source address */
  char ip6_dst[MAX_SCHEMA_STR_LENGTH];                /**< Packet destination address */
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
  uint16_t res1;                 /**< Packet res1 flag */
  uint16_t doff;                 /**< Packet doff flag */
  uint16_t fin;                  /**< Packet fin flag */
  uint16_t syn;                  /**< Packet syn flag */
  uint16_t rst;                  /**< Packet rst flag */
  uint16_t psh;                  /**< Packet psh flag */
  uint16_t ack;                  /**< Packet ack flag */
  uint16_t urg;                  /**< Packet urg flag */
  uint16_t window;              /**< Packet window */
  uint16_t check_p;               /**< Packet check */
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
  uint16_t check_p;               /**< Packet udp checksum */
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
  uint8_t type;		              /**< Packet message type */
  uint8_t code;		              /**< Packet type sub-code */
  uint16_t checksum;            /**< Packet checksum */
  uint32_t gateway;	            /**< Packet gateway address */
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
  uint16_t tid;		              /**< Packet Transaction ID */
  uint16_t flags;	              /**< Packet Flags */
  uint16_t nqueries;	          /**< Packet Questions */
  uint16_t nanswers;	          /**< Packet Answers */
  uint16_t nauth;		            /**< Packet Authority PRs */
  uint16_t nother;		          /**< Packet Other PRs */
};

/**
 * @brief DHCP protocol schema definition
 * 
 */
struct dhcp_schema {
  uint32_t hash;                                      /**< Packet hash */
  uint64_t timestamp;                                 /**< Packet timestamp */
  uint32_t caplen;                                    /**< Packet caplen */
  uint32_t length;                                    /**< Packet length */
  uint8_t  op;                                        /**< Packet packet type */
  uint8_t  htype;                                     /**< Packet type of hardware address for this machine (Ethernet, etc) */
  uint8_t  hlen;                                      /**< Packet length of hardware address (of this machine) */
  uint8_t  hops;                                      /**< Packet hops */
  uint32_t xid;                                       /**< Packet random transaction id number - chosen by this machine */
  uint16_t secs;                                      /**< Packet seconds used in timing */
  uint16_t flags;                                     /**< Packet flags */
  char ciaddr[MAX_SCHEMA_STR_LENGTH];                 /**< Packet IP address of this machine (if we already have one) */
  char yiaddr[MAX_SCHEMA_STR_LENGTH];                 /**< Packet IP address of this machine (offered by the DHCP server) */
  char siaddr[MAX_SCHEMA_STR_LENGTH];                 /**< Packet IP address of DHCP server */
  char giaddr[MAX_SCHEMA_STR_LENGTH];                 /**< Packet IP address of DHCP relay */
};

struct sqlite_context {
  sqlite3 *db;
  char grpc_srv_addr[MAX_WEB_PATH_LEN];
  char db_name[MAX_DB_NAME];
  struct string_queue *squeue;
};

/**
 * @brief Save packets to sqlite db
 * 
 * @param ctx The sqlite context structure
 * @param tp The packet tuple structure
 */
void save_packet_statement(struct sqlite_context *ctx, struct tuple_packet *tp);

/**
 * @brief Synchronises the sqlite statements with the cloud db
 * 
 * @param ctx The sqlite context structure
 * @return int 0 on success, -1 on failure
 */
int sqlite_sync_statements(struct sqlite_context *ctx);

/**
 * @brief Opens the sqlite3 database
 * 
 * @param db_path The path to sqlite3 db
 * @param db_name The name of the db
 * @param grpc_srv_addr The address of the grpc server for syncing
 * @return struct sqlite_context* pointer to the sqlite context, NULL on failure
 */
struct sqlite_context* open_sqlite_db(char *db_path, char *db_name, char *grpc_srv_addr);

/**
 * @brief Closes the sqlite db and frees the context
 * 
 * @param ctx The sqlite context structure
 */
void free_sqlite_db(struct sqlite_context *ctx);
#endif
