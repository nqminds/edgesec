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
 * @file sqlite_header_writer.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the sqlite header writer utilities.
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

#include "sqlite_header_writer.h"
#include "packet_decoder.h"

#include "../utils/os.h"
#include "../utils/if.h"
#include "../utils/log.h"
#include "../utils/sqliteu.h"

#define EXTRACT_META_PACKET(term, tp)           \
            term.hash = tp->mp.hash;            \
            term.timestamp = tp->mp.timestamp;  \
            term.caplen = tp->mp.caplen;        \
            term.length = tp->mp.length;

struct header_context {
  trace_callback_fn trace_fn;
  uint8_t *trace_ctx;
};

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

int extract_eth_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct ether_header *ethh = (struct ether_header *)tp->packet;
  sqlite3_stmt *res = NULL;
  int column_idx, rc;
  char ether_dhost[MAX_SCHEMA_STR_LENGTH];
  char ether_shost[MAX_SCHEMA_STR_LENGTH];

  if (ethh == NULL) {
    log_trace("ethh is NULL");
    return -1;
  }

  rc = sqlite3_prepare_v2(db, ETH_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    snprintf(ether_dhost, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(ethh->ether_dhost));
    column_idx = sqlite3_bind_parameter_index(res, "@ether_dhost");
    sqlite3_bind_text(res, column_idx, ether_dhost, -1, NULL);

    snprintf(ether_shost, MAX_SCHEMA_STR_LENGTH, MACSTR, MAC2STR(ethh->ether_shost));
    column_idx = sqlite3_bind_parameter_index(res, "@ether_shost");
    sqlite3_bind_text(res, column_idx, ether_shost, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ether_type");
    sqlite3_bind_int64(res, column_idx, ethh->ether_type);

    log_trace("sqlite insert eth ether_type=0x%x ether_dhost=%s ether_shost=%s", ethh->ether_type, ether_dhost, ether_shost);

    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_arp_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct ether_arp *arph = (struct ether_arp *)tp->packet;
  int column_idx, rc;
  char arp_sha[MAX_SCHEMA_STR_LENGTH];
  char arp_spa[MAX_SCHEMA_STR_LENGTH];
  char arp_tha[MAX_SCHEMA_STR_LENGTH];
  char arp_tpa[MAX_SCHEMA_STR_LENGTH];
  sqlite3_stmt *res = NULL;
  
  if (arph == NULL) {
    log_trace("arph is NULL");
    return -1;
  }
  
  rc = sqlite3_prepare_v2(db, ARP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
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

    log_trace("sqlite insert arp ar_hrd=%d arp_sha=%s arp_spa=%s arp_tha=%s arp_tpa=%s", arph->arp_hrd, arp_sha, arp_spa, arp_tha, arp_tpa);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_ip4_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct ip *ip4h = (struct ip *)tp->packet;
  int column_idx, rc;
  char ip_src[MAX_SCHEMA_STR_LENGTH];
  char ip_dst[MAX_SCHEMA_STR_LENGTH];
  sqlite3_stmt *res = NULL;

  if (ip4h == NULL) {
    log_trace("ip4h is NULL");
    return -1;
  }

  rc = sqlite3_prepare_v2(db, IP4_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
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

    inaddr4_2_ip(&(ip4h->ip_src), ip_src);
    column_idx = sqlite3_bind_parameter_index(res, "@ip_src");
    sqlite3_bind_text(res, column_idx, ip_src, -1, NULL);

    inaddr4_2_ip(&(ip4h->ip_dst), ip_dst);
    column_idx = sqlite3_bind_parameter_index(res, "@ip_dst");
    sqlite3_bind_text(res, column_idx, ip_dst, -1, NULL);

    log_trace("sqlite insert IP4 ip_p=%d ip_v=%d ip_src=%s ip_dst=%s", ip4h->ip_p, ip4h->ip_v, ip_src, ip_dst);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_ip6_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct ip6_hdr *ip6h = (struct ip6_hdr *)tp->packet;
  int column_idx, rc;
  char ip6_src[MAX_SCHEMA_STR_LENGTH];
  char ip6_dst[MAX_SCHEMA_STR_LENGTH];

  sqlite3_stmt *res = NULL;
  
  if (ip6h == NULL) {
    log_trace("ip6h is NULL");
    return -1;
  }

  rc = sqlite3_prepare_v2(db, IP6_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_flow");
    sqlite3_bind_int64(res, column_idx, ip6h->ip6_flow);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_plen");
    sqlite3_bind_int64(res, column_idx, ip6h->ip6_plen);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_nxt");
    sqlite3_bind_int64(res, column_idx, ip6h->ip6_nxt);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_hlim");
    sqlite3_bind_int64(res, column_idx, ip6h->ip6_hlim);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un2_vfc");
    sqlite3_bind_int64(res, column_idx, ip6h->ip6_vfc);

    inaddr6_2_ip(&(ip6h->ip6_src), ip6_src);
    column_idx = sqlite3_bind_parameter_index(res, "@ip6_src");
    sqlite3_bind_text(res, column_idx, ip6_src, -1, NULL);

    inaddr6_2_ip(&(ip6h->ip6_dst), ip6_dst);
    column_idx = sqlite3_bind_parameter_index(res, "@ip6_dst");
    sqlite3_bind_text(res, column_idx, ip6_dst, -1, NULL);

    log_trace("sqlite insert IP6 ip6_src=%s ip6_dst=%s ip6_un1_nxt=%d", ip6_src, ip6_dst, ip6h->ip6_nxt);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_tcp_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct tcphdr *tcph = (struct tcphdr *)tp->packet;
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  if (tcph == NULL) {
    log_trace("tcph is NULL");
    return -1;
  }
  
  rc = sqlite3_prepare_v2(db, TCP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@source");
    sqlite3_bind_int64(res, column_idx, ntohs(tcph->source));

    column_idx = sqlite3_bind_parameter_index(res, "@dest");
    sqlite3_bind_int64(res, column_idx, ntohs(tcph->dest));

    column_idx = sqlite3_bind_parameter_index(res, "@seq");
    sqlite3_bind_int64(res, column_idx, tcph->seq);

    column_idx = sqlite3_bind_parameter_index(res, "@ack_seq");
    sqlite3_bind_int64(res, column_idx, tcph->ack_seq);

    column_idx = sqlite3_bind_parameter_index(res, "@res1");
    sqlite3_bind_int64(res, column_idx, tcph->res1);

    column_idx = sqlite3_bind_parameter_index(res, "@doff");
    sqlite3_bind_int64(res, column_idx, tcph->doff);

    column_idx = sqlite3_bind_parameter_index(res, "@fin");
    sqlite3_bind_int64(res, column_idx, tcph->fin);

    column_idx = sqlite3_bind_parameter_index(res, "@syn");
    sqlite3_bind_int64(res, column_idx, tcph->syn);

    column_idx = sqlite3_bind_parameter_index(res, "@rst");
    sqlite3_bind_int64(res, column_idx, tcph->rst);

    column_idx = sqlite3_bind_parameter_index(res, "@psh");
    sqlite3_bind_int64(res, column_idx, tcph->psh);

    column_idx = sqlite3_bind_parameter_index(res, "@ack");
    sqlite3_bind_int64(res, column_idx, tcph->ack);

    column_idx = sqlite3_bind_parameter_index(res, "@urg");
    sqlite3_bind_int64(res, column_idx, tcph->urg);

    column_idx = sqlite3_bind_parameter_index(res, "@window");
    sqlite3_bind_int64(res, column_idx, tcph->window);

    column_idx = sqlite3_bind_parameter_index(res, "@check_p");
    sqlite3_bind_int64(res, column_idx, tcph->check);

    column_idx = sqlite3_bind_parameter_index(res, "@urg_ptr");
    sqlite3_bind_int64(res, column_idx, tcph->urg_ptr);

    log_trace("sqlite insert TCP source=%d dest=%d", ntohs(tcph->source), ntohs(tcph->dest));
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_udp_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct udphdr *udph = (struct udphdr *)tp->packet;
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  if (udph == NULL) {
    log_trace("udph is NULL");
    return -1;
  }
  
  rc = sqlite3_prepare_v2(db, UDP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@source");
    sqlite3_bind_int64(res, column_idx, ntohs(udph->source));

    column_idx = sqlite3_bind_parameter_index(res, "@dest");
    sqlite3_bind_int64(res, column_idx, ntohs(udph->dest));

    column_idx = sqlite3_bind_parameter_index(res, "@len");
    sqlite3_bind_int64(res, column_idx, udph->len);

    column_idx = sqlite3_bind_parameter_index(res, "@check_p");
    sqlite3_bind_int64(res, column_idx, udph->check);

    log_trace("sqlite insert UDP source=%d dest=%d", ntohs(udph->source), ntohs(udph->dest));
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_icmp4_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct icmphdr *icmp4h = (struct icmphdr *)tp->packet;
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  if (icmp4h == NULL) {
    log_trace("icmp4h is NULL");
    return -1;
  }
  
  rc = sqlite3_prepare_v2(db, ICMP4_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@type");
    sqlite3_bind_int64(res, column_idx, icmp4h->type);

    column_idx = sqlite3_bind_parameter_index(res, "@code");
    sqlite3_bind_int64(res, column_idx, icmp4h->code);

    column_idx = sqlite3_bind_parameter_index(res, "@checksum");
    sqlite3_bind_int64(res, column_idx, icmp4h->checksum);

    column_idx = sqlite3_bind_parameter_index(res, "@gateway");
    sqlite3_bind_int64(res, column_idx, icmp4h->un.gateway);

    log_trace("sqlite insert ICMP4 type=%d code=%d", icmp4h->type, icmp4h->code);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_icmp6_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)tp->packet;
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  if (icmp6h == NULL) {
    log_trace("icmp6h is NULL");
    return -1;
  }
  
  rc = sqlite3_prepare_v2(db, ICMP6_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_type");
    sqlite3_bind_int64(res, column_idx, icmp6h->icmp6_type);

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_code");
    sqlite3_bind_int64(res, column_idx, icmp6h->icmp6_code);

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_cksum");
    sqlite3_bind_int64(res, column_idx, icmp6h->icmp6_cksum);

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_un_data32");
    sqlite3_bind_int64(res, column_idx, icmp6h->icmp6_dataun.icmp6_un_data32[0]);

    log_trace("sqlite insert ICMP6 type=%d code=%d", icmp6h->icmp6_type, icmp6h->icmp6_code);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_dns_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct dns_header *dnsh = (struct dns_header *)tp->packet;
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  if (dnsh == NULL) {
    log_trace("dnsh is NULL");
    return -1;
  }
  
  rc = sqlite3_prepare_v2(db, DNS_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@tid");
    sqlite3_bind_int64(res, column_idx, dnsh->tid);

    column_idx = sqlite3_bind_parameter_index(res, "@flags");
    sqlite3_bind_int64(res, column_idx, dnsh->flags);

    column_idx = sqlite3_bind_parameter_index(res, "@nqueries");
    sqlite3_bind_int64(res, column_idx, dnsh->nqueries);

    column_idx = sqlite3_bind_parameter_index(res, "@nanswers");
    sqlite3_bind_int64(res, column_idx, dnsh->nanswers);

    column_idx = sqlite3_bind_parameter_index(res, "@nauth");
    sqlite3_bind_int64(res, column_idx, dnsh->nauth);

    column_idx = sqlite3_bind_parameter_index(res, "@nother");
    sqlite3_bind_int64(res, column_idx, dnsh->nother);

    log_trace("sqlite insert DNS tid=%d", dnsh->tid);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_mdsn_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct mdns_header *mdnsh = (struct mdns_header *)tp->packet;
  int column_idx, rc;
  sqlite3_stmt *res = NULL;

  if (mdnsh == NULL) {
    log_trace("dnsh is NULL");
    return -1;
  }

  rc = sqlite3_prepare_v2(db, MDNS_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@tid");
    sqlite3_bind_int64(res, column_idx, mdnsh->tid);

    column_idx = sqlite3_bind_parameter_index(res, "@flags");
    sqlite3_bind_int64(res, column_idx, mdnsh->flags);

    column_idx = sqlite3_bind_parameter_index(res, "@nqueries");
    sqlite3_bind_int64(res, column_idx, mdnsh->nqueries);

    column_idx = sqlite3_bind_parameter_index(res, "@nanswers");
    sqlite3_bind_int64(res, column_idx, mdnsh->nanswers);

    column_idx = sqlite3_bind_parameter_index(res, "@nauth");
    sqlite3_bind_int64(res, column_idx, mdnsh->nauth);

    column_idx = sqlite3_bind_parameter_index(res, "@nother");
    sqlite3_bind_int64(res, column_idx, mdnsh->nother);

    log_trace("sqlite insert mDNS tid=%d", mdnsh->tid);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int extract_dhcp_statement(sqlite3 *db, struct tuple_packet *tp)
{
  struct dhcp_header *dhcph = (struct dhcp_header *)tp->packet;
  char ciaddr[MAX_SCHEMA_STR_LENGTH];
  char yiaddr[MAX_SCHEMA_STR_LENGTH];
  char siaddr[MAX_SCHEMA_STR_LENGTH];
  char giaddr[MAX_SCHEMA_STR_LENGTH];
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  if (dhcph == NULL) {
    log_trace("dhcph is NULL");
    return -1;
  }
  
  rc = sqlite3_prepare_v2(db, DHCP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    if (!extract_meta_params(res, &tp->mp)) {
      log_trace("extract_meta_params fail");
      sqlite3_finalize(res);
      return -1;
    }

    column_idx = sqlite3_bind_parameter_index(res, "@op");
    sqlite3_bind_int64(res, column_idx, dhcph->op);

    column_idx = sqlite3_bind_parameter_index(res, "@htype");
    sqlite3_bind_int64(res, column_idx, dhcph->htype);

    column_idx = sqlite3_bind_parameter_index(res, "@hlen");
    sqlite3_bind_int64(res, column_idx, dhcph->hlen);

    column_idx = sqlite3_bind_parameter_index(res, "@hops");
    sqlite3_bind_int64(res, column_idx, dhcph->hops);

    column_idx = sqlite3_bind_parameter_index(res, "@xid");
    sqlite3_bind_int64(res, column_idx, dhcph->xid);

    column_idx = sqlite3_bind_parameter_index(res, "@secs");
    sqlite3_bind_int64(res, column_idx, dhcph->secs);

    column_idx = sqlite3_bind_parameter_index(res, "@flags");
    sqlite3_bind_int64(res, column_idx, dhcph->flags);

    inaddr4_2_ip(&(dhcph->ciaddr), ciaddr);
    column_idx = sqlite3_bind_parameter_index(res, "@ciaddr");
    sqlite3_bind_text(res, column_idx, ciaddr, -1, NULL);

    inaddr4_2_ip(&(dhcph->yiaddr), yiaddr);
    column_idx = sqlite3_bind_parameter_index(res, "@yiaddr");
    sqlite3_bind_text(res, column_idx, yiaddr, -1, NULL);

    inaddr4_2_ip(&(dhcph->siaddr), siaddr);
    column_idx = sqlite3_bind_parameter_index(res, "@siaddr");
    sqlite3_bind_text(res, column_idx, siaddr, -1, NULL);

    inaddr4_2_ip(&(dhcph->giaddr), giaddr);
    column_idx = sqlite3_bind_parameter_index(res, "@giaddr");
    sqlite3_bind_text(res, column_idx, giaddr, -1, NULL);

    log_trace("sqlite insert DHCP ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s", ciaddr, yiaddr, siaddr, giaddr);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

int save_packet_statement(sqlite3 *db, struct tuple_packet *tp)
{
  switch (tp->mp.type) {
    case PACKET_ETHERNET:
      return extract_eth_statement(db, tp);
    case PACKET_ARP:
      return extract_arp_statement(db, tp);
    case PACKET_IP4:
      return extract_ip4_statement(db, tp);
    case PACKET_IP6:
      return extract_ip6_statement(db, tp);
    case PACKET_TCP:
      return extract_tcp_statement(db, tp);
    case PACKET_UDP:
      return extract_udp_statement(db, tp);
    case PACKET_ICMP4:
      return extract_icmp4_statement(db, tp);
    case PACKET_ICMP6:
      return extract_icmp6_statement(db, tp);
    case PACKET_DNS:
      return extract_dns_statement(db, tp);
    case PACKET_MDNS:
      return extract_mdsn_statement(db, tp);
    case PACKET_DHCP:
      return extract_dhcp_statement(db, tp);
  }

  return -1;
}

void free_sqlite_header_db(sqlite3 *db)
{
  if (db != NULL) {
    sqlite3_close(db);
  }
}

int sqlite_trace_callback(unsigned int uMask, void* ctx, void* stm, void* X)
{
  struct header_context *sql_ctx = (struct header_context *)ctx;
  sqlite3_stmt *statement = (sqlite3_stmt *)stm;
  char *sqlite_str;

  if (sql_ctx->trace_fn != NULL) {
    sqlite_str = sqlite3_expanded_sql(statement);
    sql_ctx->trace_fn(sqlite_str, sql_ctx->trace_ctx);
    sqlite3_free(sqlite_str);  
  }

  return 0;
}

int open_sqlite_header_db(char *db_path, trace_callback_fn fn,
                               void *trace_ctx, sqlite3 **sql)
{
  sqlite3 *db;
  struct header_context *ctx = NULL;

  int rc = sqlite3_open(db_path, &db);
  *sql = db;

  if (rc != SQLITE_OK) {
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  ctx = os_zalloc(sizeof(struct header_context));
  ctx->trace_fn = fn;
  ctx->trace_ctx = trace_ctx;

  if (ctx->trace_fn != NULL) {
    log_trace("Register sqlite trace callback");
    sqlite3_trace_v2(db, SQLITE_TRACE_STMT, sqlite_trace_callback, (void *)ctx);
  }

  log_debug("sqlite autocommit mode=%d", sqlite3_get_autocommit(db));

  rc = check_table_exists(db, "eth");

  if (rc == 0) {
    log_debug("eth table doesn't exist creating...");
    if (execute_sqlite_query(db, ETH_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "arp");

  if (rc == 0) {
    log_debug("arp table doesn't exist creating...");
    if (execute_sqlite_query(db, ARP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "ip4");

  if (rc == 0) {
    log_debug("ip4 table doesn't exist creating...");
    if (execute_sqlite_query(db, IP4_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "ip6");

  if (rc == 0) {
    log_debug("ip6 table doesn't exist creating...");
    if (execute_sqlite_query(db, IP6_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "tcp");

  if (rc == 0) {
    log_debug("tcp table doesn't exist creating...");
    if (execute_sqlite_query(db, TCP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "udp");

  if (rc == 0) {
    log_debug("udp table doesn't exist creating...");
    if (execute_sqlite_query(db, UDP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "icmp4");

  if (rc == 0) {
    log_debug("icmp4 table doesn't exist creating...");
    if (execute_sqlite_query(db, ICMP4_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "icmp6");

  if (rc == 0) {
    log_debug("icmp6 table doesn't exist creating...");
    if (execute_sqlite_query(db, ICMP6_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "dns");

  if (rc == 0) {
    log_debug("dns table doesn't exist creating...");
    if (execute_sqlite_query(db, DNS_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "mdns");

  if (rc == 0) {
    log_debug("mdns table doesn't exist creating...");
    if (execute_sqlite_query(db, MDNS_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  rc = check_table_exists(db, "dhcp");

  if (rc == 0) {
    log_debug("dhcp table doesn't exist creating...");
    if (execute_sqlite_query(db, DHCP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(db);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(db);
    return -1;
  }

  return 0;
}