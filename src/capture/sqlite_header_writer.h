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
 * @file sqlite_header_writer.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the sqlite header writer utilities.
 */

#ifndef SQLITE_HEADER_WRITER_H
#define SQLITE_HEADER_WRITER_H

#include <stdint.h>
#include <sqlite3.h>

// #include "packet_decoder.h"

#include "../utils/os.h"

#include "capture_config.h"

#define MAX_DB_NAME           100

#define ETH_CREATE_TABLE "CREATE TABLE eth (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, "\
                         "caplen INTEGER, length INTEGER, ifname TEXT, hostname TEXT, id TEXT NOT NULL, " \
                         "ether_dhost TEXT, ether_shost TEXT, ether_type INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define ARP_CREATE_TABLE "CREATE TABLE arp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT, "\
                         "arp_hrd INTEGER, arp_pro INTEGER, arp_hln INTEGER, " \
                         "arp_pln INTEGER, arp_op INTEGER, arp_sha TEXT, arp_spa TEXT, " \
                         "arp_tha TEXT, arp_tpa TEXT, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define IP4_CREATE_TABLE "CREATE TABLE ip4 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                         "ip_hl INTEGER, ip_v INTEGER, ip_tos INTEGER, ip_len INTEGER, ip_id INTEGER, " \
                         "ip_off INTEGER, ip_ttl INTEGER, ip_p INTEGER, ip_sum INTEGER, ip_src TEXT, " \
                         "ip_dst TEXT, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define IP6_CREATE_TABLE "CREATE TABLE ip6 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                         "ip6_un1_flow INTEGER, ip6_un1_plen INTEGER, ip6_un1_nxt INTEGER, cip6_un1_hlim INTEGER, " \
                         "ip6_un2_vfc INTEGER, ip6_src TEXT, ip6_dst TEXT, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define TCP_CREATE_TABLE "CREATE TABLE tcp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                         "source INTEGER, dest INTEGER, seq INTEGER, ack_seq INTEGER, res1 INTEGER, doff INTEGER, fin INTEGER, " \
                         "syn INTEGER, rst INTEGER, psh INTEGER, ack INTEGER, urg INTEGER, window INTEGER, check_p INTEGER, " \
                         "urg_ptr INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define UDP_CREATE_TABLE "CREATE TABLE udp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                         "source INTEGER, dest INTEGER, len INTEGER, check_p INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define ICMP4_CREATE_TABLE "CREATE TABLE icmp4 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                           "type INTEGER, code INTEGER, checksum INTEGER, gateway INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define ICMP6_CREATE_TABLE "CREATE TABLE icmp6 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                           "icmp6_type INTEGER, icmp6_code INTEGER, icmp6_cksum INTEGER, icmp6_un_data32 INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define DNS_CREATE_TABLE "CREATE TABLE dns (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                         "tid INTEGER, flags INTEGER, nqueries INTEGER, nanswers INTEGER, nauth INTEGER, " \
                         "nother INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define MDNS_CREATE_TABLE "CREATE TABLE mdns (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                          "tid INTEGER, flags INTEGER, nqueries INTEGER, nanswers INTEGER, nauth INTEGER, " \
                          "nother INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define DHCP_CREATE_TABLE "CREATE TABLE dhcp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, id TEXT NOT NULL, " \
                          "op INTEGER, htype INTEGER, hlen INTEGER, hops INTEGER, xid INTEGER, secs INTEGER, flags INTEGER, " \
                          "ciaddr TEXT, yiaddr TEXT, siaddr TEXT, giaddr TEXT, PRIMARY KEY (hash, timestamp, ethh_hash, id));"

#define ETH_INSERT_INTO "INSERT INTO eth VALUES(@hash, @timestamp, @ethh_hash, @caplen, @length, @ifname, @hostname, @id, @ether_dhost, @ether_shost, @ether_type);"
#define ARP_INSERT_INTO "INSERT INTO arp VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                        "@arp_hrd, @arp_pro, @arp_hln, @arp_pln, @arp_op, @arp_sha, @arp_spa, " \
                        "@arp_tha, @arp_tpa);"
#define IP4_INSERT_INTO "INSERT INTO ip4 VALUES(@hash, @timestamp, @ethh_hash, @id, @ip_hl, @ip_v, @ip_tos, @ip_len, @ip_id, " \
                        "@ip_off, @ip_ttl, @ip_p, @ip_sum, @ip_src, @ip_dst);"
#define IP6_INSERT_INTO "INSERT INTO ip6 VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                        "@ip6_un1_flow, @ip6_un1_plen, @ip6_un1_nxt, @cip6_un1_hlim, @ip6_un2_vfc, @ip6_src, @ip6_dst);"
#define TCP_INSERT_INTO "INSERT INTO tcp VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                        "@source, @dest, @seq, @ack_seq, @res1, @doff, @fin, " \
                        "@syn, @rst, @psh, @ack, @urg, @window, @check_p, @urg_ptr);"
#define UDP_INSERT_INTO "INSERT INTO udp VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                        "@source, @dest, @len, @check_p);"
#define ICMP4_INSERT_INTO "INSERT INTO icmp4 VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                          "@type, @code, @checksum, @gateway);"
#define ICMP6_INSERT_INTO "INSERT INTO icmp6 VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                          "@icmp6_type, @icmp6_code, @icmp6_cksum, @icmp6_un_data32);"
#define DNS_INSERT_INTO "INSERT INTO dns VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                        "@tid, @flags, @nqueries, @nanswers, @nauth, @nother);"
#define MDNS_INSERT_INTO "INSERT INTO mdns VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                         "@tid, @flags, @nqueries, @nanswers, @nauth, @nother);"
#define DHCP_INSERT_INTO "INSERT INTO dhcp VALUES(@hash, @timestamp, @ethh_hash, @id, " \
                          "@op, @htype, @hlen, @hops, @xid, @secs, @flags, " \
                          "@ciaddr, @yiaddr, @siaddr, @giaddr);"

typedef void (*trace_callback_fn)(char *sqlite_statement, void *trace_ctx);

/**
 * @brief Save packets to sqlite db
 * 
 * @param db The sqlite db
 * @param tp The packet tuple structure
 * @return int 0 on success, -1 o failure
 */
int save_packet_statement(sqlite3 *db, struct tuple_packet *tp);

/**
 * @brief Opens the sqlite3 header database
 * 
 * @param db_path The path to sqlite3 db
 * @param trace_fn The callback to the trace callback function
 * @param trace_ctx The context for trace callback
 * @param sql The returned sqlite db structure pointer
 * @return 0 on success, -1 on failure
 */
int open_sqlite_header_db(char *db_path, trace_callback_fn trace_fn,
                                void *trace_ctx, sqlite3 **sql);

/**
 * @brief Closes the sqlite db
 * 
 * @param ctx The sqlite db
 */
void free_sqlite_header_db(sqlite3 *db);

#endif
