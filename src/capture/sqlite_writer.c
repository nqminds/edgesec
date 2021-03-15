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
 * @file sqlite_writer.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the sqlite writer utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#include <sqlite3.h>

#include "sqlite_writer.h"
#include "packet_decoder.h"
#include "../utils/os.h"
#include "../utils/if.h"
#include "../utils/log.h"

#define EXTRACT_META_PACKET(term, tp)           \
            term.hash = tp->mp.hash;            \
            term.timestamp = tp->mp.timestamp;  \
            term.caplen = tp->mp.caplen;        \
            term.length = tp->mp.length;

bool extract_meta_params(sqlite3_stmt *res, struct meta_packet *mp)
{
  int column_idx;

  column_idx = sqlite3_bind_parameter_index(res, "@hash");
  if (sqlite3_bind_int64(res, column_idx, mp->hash) != SQLITE_OK)
    return false;

  column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
  if (sqlite3_bind_int64(res, column_idx, mp->ethh_hash) != SQLITE_OK)
    return false;

  //>>> Correct truncation problem
  column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
  if(sqlite3_bind_int64(res, column_idx, mp->timestamp) != SQLITE_OK)
    return false;

  column_idx = sqlite3_bind_parameter_index(res, "@caplen");
  if (sqlite3_bind_int64(res, column_idx, mp->caplen) != SQLITE_OK)
    return false;

  column_idx = sqlite3_bind_parameter_index(res, "@length");
  if (sqlite3_bind_int64(res, column_idx, mp->length) != SQLITE_OK)
    return false;

  return true;
}

void extract_eth_statement(struct sqlite_context *ctx, struct tuple_packet *tp)
{
  struct ether_header *ethh = (struct ether_header *)tp->packet;
  sqlite3_stmt *res = NULL;
  int column_idx;
  char ether_dhost[MAX_SCHEMA_STR_LENGTH];
  char ether_shost[MAX_SCHEMA_STR_LENGTH];

  int rc = sqlite3_prepare_v2(ctx->db, ETH_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return;
    }

    snprintf(ether_dhost, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(ethh->ether_dhost));
    column_idx = sqlite3_bind_parameter_index(res, "@ether_dhost");
    sqlite3_bind_text(res, column_idx, ether_dhost, -1, NULL);

    snprintf(ether_shost, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(ethh->ether_shost));
    column_idx = sqlite3_bind_parameter_index(res, "@ether_shost");
    sqlite3_bind_text(res, column_idx, ether_shost, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ether_type");
    sqlite3_bind_int64(res, column_idx, ethh->ether_type);

    log_trace("sqlite insert eth type=0x%x", ethh->ether_type);

    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
  }
}

void extract_arp_statement(struct sqlite_context *ctx, struct tuple_packet *tp)
{
  struct ether_arp *arph = (struct ether_arp *)tp->packet;
  int column_idx;
  char arp_sha[MAX_SCHEMA_STR_LENGTH];
  char arp_spa[MAX_SCHEMA_STR_LENGTH];
  char arp_tha[MAX_SCHEMA_STR_LENGTH];
  char arp_tpa[MAX_SCHEMA_STR_LENGTH];
  sqlite3_stmt *res = NULL;
  int rc = sqlite3_prepare_v2(ctx->db, ARP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@arp_hrd");
    sqlite3_bind_int64(res, column_idx, arph->arp_hrd);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_pro");
    sqlite3_bind_int64(res, column_idx, arph->arp_pro);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_hln");
    sqlite3_bind_int64(res, column_idx, arph->arp_hln);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_pln");
    sqlite3_bind_int64(res, column_idx, arph->arp_pln);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_op");
    sqlite3_bind_int64(res, column_idx, arph->arp_op);

    snprintf(arp_sha, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(arph->arp_sha));
    column_idx = sqlite3_bind_parameter_index(res, "@arp_sha");
    sqlite3_bind_text(res, column_idx, arp_sha, -1, NULL);

    snprintf(arp_spa, MAX_SCHEMA_STR_LENGTH, IPSTR, IP2STR(arph->arp_spa));
    column_idx = sqlite3_bind_parameter_index(res, "@arp_spa");
    sqlite3_bind_text(res, column_idx, arp_spa, -1, NULL);


    snprintf(arp_tha, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(arph->arp_tha));
    column_idx = sqlite3_bind_parameter_index(res, "@arp_tha");
    sqlite3_bind_text(res, column_idx, arp_tha, -1, NULL);

    snprintf(arp_tpa, MAX_SCHEMA_STR_LENGTH, IPSTR, IP2STR(arph->arp_tpa));
    column_idx = sqlite3_bind_parameter_index(res, "@arp_tpa");
    sqlite3_bind_text(res, column_idx, arp_tpa, -1, NULL);

    log_trace("sqlite insert arp arp_hrd=%d", arph->arp_hrd);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
  }
}

void extract_ip4_statement(struct sqlite_context *ctx, struct tuple_packet *tp)
{
  struct ip *ip4h = (struct ip *)tp->packet;
  int column_idx;
  char text_field[MAX_SCHEMA_STR_LENGTH];
  sqlite3_stmt *res = NULL;
  int rc = sqlite3_prepare_v2(ctx->db, IP4_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@ip_hl");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_hl);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_v");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_v);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_tos");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_tos);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_len");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_len);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_id");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_id);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_off");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_off);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_ttl");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_ttl);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_p");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_p);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_sum");
    sqlite3_bind_int64(res, column_idx, ip4h->ip_sum);

    inaddr4_2_ip(&(ip4h->ip_src), text_field);
    column_idx = sqlite3_bind_parameter_index(res, "@ip_src");
    sqlite3_bind_text(res, column_idx, text_field, -1, NULL);

    inaddr4_2_ip(&(ip4h->ip_dst), text_field);
    column_idx = sqlite3_bind_parameter_index(res, "@ip_dst");
    sqlite3_bind_text(res, column_idx, text_field, -1, NULL);

    log_trace("sqlite insert IP4 ip_p=%d ip_v=%d", ip4h->ip_p, ip4h->ip_v);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
  }
}

struct ip6_schema extract_ip6_statement(struct tuple_packet *tp)
{
  struct ip6_schema ip6s;
  struct ip6_hdr *ip6h = (struct ip6_hdr *)tp->packet;

  EXTRACT_META_PACKET(ip6s, tp)

  ip6s.ip6_un1_flow = ip6h->ip6_flow;
  ip6s.ip6_un1_plen = ip6h->ip6_plen;
  ip6s.ip6_un1_nxt = ip6h->ip6_nxt;
  ip6s.ip6_un1_hlim = ip6h->ip6_hlim;
  ip6s.ip6_un2_vfc = ip6h->ip6_vfc;

  inaddr6_2_ip(&(ip6h->ip6_src), ip6s.ip6_src);
  inaddr6_2_ip(&(ip6h->ip6_dst), ip6s.ip6_dst);

  log_trace("IP6 ip6_src=%s ip6_dst=%s ip6_un1_nxt=%d", ip6s.ip6_src, ip6s.ip6_dst, ip6s.ip6_un1_nxt);

  return ip6s;
}

struct tcp_schema extract_tcp_statement(struct tuple_packet *tp)
{
  struct tcp_schema tcps;
  struct tcphdr *tcph = (struct tcphdr *)tp->packet;
  
  EXTRACT_META_PACKET(tcps, tp)

  tcps.source = ntohs(tcph->source);
  tcps.dest = ntohs(tcph->dest);
  tcps.seq = tcph->seq;
  tcps.ack_seq = tcph->ack_seq;
  tcps.res1 = tcph->res1;
  tcps.doff = tcph->doff;
  tcps.fin = tcph->fin;
  tcps.syn = tcph->syn;
  tcps.rst = tcph->rst;
  tcps.psh = tcph->psh;
  tcps.ack = tcph->ack;
  tcps.urg = tcph->urg;
  tcps.window = tcph->window;
  tcps.check_p = tcph->check;
  tcps.urg_ptr = tcph->urg_ptr;
  
  log_trace("TCP source=%d dest=%d", tcps.source, tcps.dest);
  return tcps;
}

struct udp_schema extract_udp_statement(struct tuple_packet *tp)
{
  struct udp_schema udps;
  struct udphdr *udph = (struct udphdr *)tp->packet;
  
  EXTRACT_META_PACKET(udps, tp)

  udps.source = ntohs(udph->source);
  udps.dest = ntohs(udph->dest);
  udps.len = udph->len;
  udps.check_p = udph->check;

  log_trace("UDP source=%d dest=%d", udps.source, udps.dest);
  return udps;
}

struct icmp4_schema extract_icmp4_statement(struct tuple_packet *tp)
{
  struct icmp4_schema icmp4s;
  struct icmphdr *icmp4h = (struct icmphdr *)tp->packet;
  
  EXTRACT_META_PACKET(icmp4s, tp)

  icmp4s.type = icmp4h->type;
  icmp4s.code = icmp4h->code;
  icmp4s.checksum = icmp4h->checksum;
  icmp4s.gateway = icmp4h->un.gateway;

  log_trace("ICMP4 type=%d code=%d", icmp4s.type, icmp4s.code);
  return icmp4s;
}

struct icmp6_schema extract_icmp6_statement(struct tuple_packet *tp)
{
  struct icmp6_schema icmp6s;
  struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)tp->packet;
  
  EXTRACT_META_PACKET(icmp6s, tp)

  icmp6s.icmp6_type = icmp6h->icmp6_type;
  icmp6s.icmp6_code = icmp6h->icmp6_code;
  icmp6s.icmp6_cksum = icmp6h->icmp6_cksum;
  icmp6s.icmp6_un_data32 = icmp6h->icmp6_dataun.icmp6_un_data32[0];

  log_trace("ICMP6 type=%d code=%d", icmp6s.icmp6_type, icmp6s.icmp6_code);
  return icmp6s;
}

struct dns_schema extract_dns_statement(struct tuple_packet *tp)
{
  struct dns_schema dnss;
  struct dns_header *dnsh = (struct dns_header *)tp->packet;

  EXTRACT_META_PACKET(dnss, tp)

  dnss.tid = dnsh->tid;
  dnss.flags = dnsh->flags;
  dnss.nqueries = dnsh->nqueries;
  dnss.nanswers = dnsh->nanswers;
  dnss.nauth = dnsh->nauth;
  dnss.nother = dnsh->nother;

  log_trace("DNS");

  return dnss;
}

struct mdns_schema extract_mdsn_statement(struct tuple_packet *tp)
{
  struct mdns_schema mdnss;
  struct mdns_header *mdnsh = (struct mdns_header *)tp->packet;

  EXTRACT_META_PACKET(mdnss, tp)

  mdnss.tid = mdnsh->tid;
  mdnss.flags = mdnsh->flags;
  mdnss.nqueries = mdnsh->nqueries;
  mdnss.nanswers = mdnsh->nanswers;
  mdnss.nauth = mdnsh->nauth;
  mdnss.nother = mdnsh->nother;

  log_trace("mDNS");

  return mdnss;
}

struct dhcp_schema extract_dhcp_statement(struct tuple_packet *tp)
{
  struct dhcp_schema dhcps;
  struct dhcp_header *dhcph = (struct dhcp_header *)tp->packet;
  
  EXTRACT_META_PACKET(dhcps, tp)

  dhcps.op = dhcph->op;
  dhcps.htype = dhcph->htype;
  dhcps.hlen = dhcph->hlen;
  dhcps.hops = dhcph->hops;
  dhcps.xid = dhcph->xid;
  dhcps.secs = dhcph->secs;
  dhcps.flags = dhcph->flags;
  inaddr4_2_ip(&(dhcph->ciaddr), dhcps.ciaddr);
  inaddr4_2_ip(&(dhcph->yiaddr), dhcps.yiaddr);
  inaddr4_2_ip(&(dhcph->siaddr), dhcps.siaddr);
  inaddr4_2_ip(&(dhcph->giaddr), dhcps.giaddr);
  
  log_trace("DHCP");
  return dhcps;
}

void extract_statements(struct sqlite_context *ctx, struct tuple_packet *tp)
{
  struct ip6_schema ip6s;
  struct tcp_schema tcps;
  struct udp_schema udps;
  struct icmp4_schema icmp4s;
  struct icmp6_schema icmp6s;
  struct dns_schema dnss;
  struct mdns_schema mdnss;
  struct dhcp_schema dhcps;
  switch (tp->mp.type) {
    case PACKET_ETHERNET:
      extract_eth_statement(ctx, tp);
      return;
    case PACKET_ARP:
      extract_arp_statement(ctx, tp);
      return;
    case PACKET_IP4:
      extract_ip4_statement(ctx, tp);
      return;
    case PACKET_IP6:
      ip6s = extract_ip6_statement(tp);
      return;
    case PACKET_TCP:
      tcps = extract_tcp_statement(tp);
      return;
    case PACKET_UDP:
      udps = extract_udp_statement(tp);
      return;
    case PACKET_ICMP4:
      icmp4s = extract_icmp4_statement(tp);
      return;
    case PACKET_ICMP6:
      icmp6s = extract_icmp6_statement(tp);
      return;
    case PACKET_DNS:
      dnss = extract_dns_statement(tp);
      return;
    case PACKET_MDNS:
      mdnss = extract_mdsn_statement(tp);
      return;
    case PACKET_DHCP:
      dhcps = extract_dhcp_statement(tp);
      return;
  }
}

int execute_sqlite_query(struct sqlite_context *ctx, char *statement)
{
  char *err = NULL;
  int rc = sqlite3_exec(ctx->db, statement, 0, 0, &err);

  if (rc != SQLITE_OK ) {
    log_debug("Failed to execute statement %s", err);
    sqlite3_free(err);
    
    return -1;
  }

  return 0;
}

int check_table_exists(struct sqlite_context *ctx, char *table_name)
{
  sqlite3_stmt *res;
  char *sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
  int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &res, 0);


  if (rc == SQLITE_OK)
    sqlite3_bind_text(res, 1, table_name, -1, NULL);
  else {
    log_debug("Failed to execute statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  log_trace("%s", sql);
  rc = sqlite3_step(res);

  if (rc == SQLITE_ROW) {
    log_trace("Found table %s", sqlite3_column_text(res, 0));
    sqlite3_finalize(res);
    return 1;
  }

  return 0;
}

void free_sqlite_db(struct sqlite_context *ctx)
{
  if (ctx != NULL) {
    sqlite3_close(ctx->db);
    os_free(ctx);
  }
}

struct sqlite_context* open_sqlite_db(char *db_path)
{
  sqlite3 *db;
  struct sqlite_context *ctx = NULL;

  int rc = sqlite3_open(db_path, &db);
  if (rc != SQLITE_OK) {     
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return ctx;
  }

  log_debug("sqlite autocommit mode=%d", sqlite3_get_autocommit(db));

  ctx = os_malloc(sizeof(struct sqlite_context));
  ctx->db = db;
  
  rc = check_table_exists(ctx, "eth");

  if (rc == 0) {
    log_debug("eth table doesn't exist creating...");
    if (execute_sqlite_query(ctx, ETH_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "arp");

  if (rc == 0) {
    log_debug("arp table doesn't exist creating...");
    if (execute_sqlite_query(ctx, ARP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "ip4");

  if (rc == 0) {
    log_debug("ip4 table doesn't exist creating...");
    if (execute_sqlite_query(ctx, IP4_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "ip6");

  if (rc == 0) {
    log_debug("ip6 table doesn't exist creating...");
    if (execute_sqlite_query(ctx, IP6_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "tcp");

  if (rc == 0) {
    log_debug("tcp table doesn't exist creating...");
    if (execute_sqlite_query(ctx, TCP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "udp");

  if (rc == 0) {
    log_debug("udp table doesn't exist creating...");
    if (execute_sqlite_query(ctx, UDP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "icmp4");

  if (rc == 0) {
    log_debug("icmp4 table doesn't exist creating...");
    if (execute_sqlite_query(ctx, ICMP4_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "icmp6");

  if (rc == 0) {
    log_debug("icmp6 table doesn't exist creating...");
    if (execute_sqlite_query(ctx, ICMP6_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "dns");

  if (rc == 0) {
    log_debug("dns table doesn't exist creating...");
    if (execute_sqlite_query(ctx, DNS_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "mdns");

  if (rc == 0) {
    log_debug("mdns table doesn't exist creating...");
    if (execute_sqlite_query(ctx, MDNS_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "dhcp");

  if (rc == 0) {
    log_debug("dhcp table doesn't exist creating...");
    if (execute_sqlite_query(ctx, DHCP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_db(ctx);
      return NULL;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  return ctx;
}
