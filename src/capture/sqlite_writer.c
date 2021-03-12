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

struct eth_schema extract_eth_schema(struct tuple_packet *tp)
{
  struct eth_schema eths;
  struct ether_header *ethh = (struct ether_header *)tp->packet;
  
  EXTRACT_META_PACKET(eths, tp)

  snprintf(eths.ether_dhost, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(ethh->ether_dhost));
  snprintf(eths.ether_shost, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(ethh->ether_shost));
  eths.ether_type = ethh->ether_type;
  
  log_trace("Ethernet type=0x%x ether_dhost=%s ether_shost=%s",
            eths.ether_type, eths.ether_dhost, eths.ether_shost);
  return eths;
}

struct arp_schema extract_arp_schema(struct tuple_packet *tp)
{
  struct arp_schema arps;
  struct ether_arp *arph = (struct ether_arp *)tp->packet;

  EXTRACT_META_PACKET(arps, tp)

  arps.ar_hrd = arph->arp_hrd;
  arps.ar_pro = arph->arp_pro;
  arps.ar_hln = arph->arp_hln;
  arps.ar_pln = arph->arp_pln;
  arps.ar_op = arph->arp_op;

  snprintf(arps.arp_sha, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(arph->arp_sha));
  snprintf(arps.arp_spa, MAX_SCHEMA_STR_LENGTH, IPSTR, IP2STR(arph->arp_spa));
  snprintf(arps.arp_tha, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(arph->arp_tha));
  snprintf(arps.arp_tpa, MAX_SCHEMA_STR_LENGTH, IPSTR, IP2STR(arph->arp_tpa));

  log_trace("ARP arp_sha=%s arp_spa=%s arp_tha=%s arp_tpa=%s",
            arps.arp_sha, arps.arp_spa, arps.arp_tha, arps.arp_tpa);

  return arps;
}

struct ip4_schema extract_ip4_schema(struct tuple_packet *tp)
{
  struct ip4_schema ip4s;
  struct ip *ip4h = (struct ip *)tp->packet;

  EXTRACT_META_PACKET(ip4s, tp)

  ip4s.ip_hl = ip4h->ip_hl;
  ip4s.ip_v = ip4h->ip_v;
  ip4s.ip_tos = ip4h->ip_tos;
  ip4s.ip_len = ip4h->ip_len;
  ip4s.ip_id = ip4h->ip_id;
  ip4s.ip_off = ip4h->ip_off;
  ip4s.ip_ttl = ip4h->ip_ttl;
  ip4s.ip_p = ip4h->ip_p;
  ip4s.ip_sum = ip4h->ip_sum;
  inaddr4_2_ip(&(ip4h->ip_src), ip4s.ip_src);
  inaddr4_2_ip(&(ip4h->ip_dst), ip4s.ip_dst);

  log_trace("IP4 ip_src=%s ip_dst=%s ip_p=%d ip_v=%d", ip4s.ip_src, ip4s.ip_dst, ip4s.ip_p, ip4s.ip_v);
  return ip4s;
}

struct ip6_schema extract_ip6_schema(struct tuple_packet *tp)
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

struct tcp_schema extract_tcp_schema(struct tuple_packet *tp)
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
  tcps.check = tcph->check;
  tcps.urg_ptr = tcph->urg_ptr;
  
  log_trace("TCP source=%d dest=%d", tcps.source, tcps.dest);
  return tcps;
}

struct udp_schema extract_udp_schema(struct tuple_packet *tp)
{
  struct udp_schema udps;
  struct udphdr *udph = (struct udphdr *)tp->packet;
  
  EXTRACT_META_PACKET(udps, tp)

  udps.source = ntohs(udph->source);
  udps.dest = ntohs(udph->dest);
  udps.len = udph->len;
  udps.check = udph->check;

  log_trace("UDP source=%d dest=%d", udps.source, udps.dest);
  return udps;
}

struct icmp4_schema extract_icmp4_schema(struct tuple_packet *tp)
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

struct icmp6_schema extract_icmp6_schema(struct tuple_packet *tp)
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

struct dns_schema extract_dns_schema(struct tuple_packet *tp)
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

struct mdns_schema extract_mdsn_schema(struct tuple_packet *tp)
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

struct dhcp_schema extract_dhcp_schema(struct tuple_packet *tp)
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

void extract_schema(struct tuple_packet *tp)
{
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
  switch (tp->mp.type) {
    case PACKET_ETHERNET:
      eths = extract_eth_schema(tp);
      return;
    case PACKET_ARP:
      arps = extract_arp_schema(tp);
      return;
    case PACKET_IP4:
      ip4s = extract_ip4_schema(tp);
      return;
    case PACKET_IP6:
      ip6s = extract_ip6_schema(tp);
      return;
    case PACKET_TCP:
      tcps = extract_tcp_schema(tp);
      return;
    case PACKET_UDP:
      udps = extract_udp_schema(tp);
      return;
    case PACKET_ICMP4:
      icmp4s = extract_icmp4_schema(tp);
      return;
    case PACKET_ICMP6:
      icmp6s = extract_icmp6_schema(tp);
      return;
    case PACKET_DNS:
      dnss = extract_dns_schema(tp);
      return;
    case PACKET_MDNS:
      mdnss = extract_mdsn_schema(tp);
      return;
    case PACKET_DHCP:
      dhcps = extract_dhcp_schema(tp);
      return;
  }
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
  ctx = os_malloc(sizeof(struct sqlite_context));
  ctx->db = db;
  
  rc = check_table_exists(ctx, "eth");

  if (rc == 0) {
    log_debug("eth table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "arp");

  if (rc == 0) {
    log_debug("arp table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "ip4");

  if (rc == 0) {
    log_debug("ip4 table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "ip6");

  if (rc == 0) {
    log_debug("ip6 table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "tcp");

  if (rc == 0) {
    log_debug("tcp table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "udp");

  if (rc == 0) {
    log_debug("udp table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "icmp4");

  if (rc == 0) {
    log_debug("icmp4 table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "icmp6");

  if (rc == 0) {
    log_debug("icmp6 table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "dns");

  if (rc == 0) {
    log_debug("dns table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "mdns");

  if (rc == 0) {
    log_debug("mdns table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  rc = check_table_exists(ctx, "dhcp");

  if (rc == 0) {
    log_debug("dhcp table doesn't exist creating...");
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_db(ctx);
    return NULL;
  }

  return ctx;
}
