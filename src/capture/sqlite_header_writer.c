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
#include <sqlite3.h>

#include "sqlite_header_writer.h"
#include "packet_decoder.h"

#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/if.h"
#include "../utils/log.h"
#include "../utils/sqliteu.h"

#define EXTRACT_META_PACKET(term, tp)           \
            term.hash = tp->mp.hash;            \
            term.timestamp = tp->mp.timestamp;  \
            term.caplen = tp->mp.caplen;        \
            term.length = tp->mp.length;

int extract_eth_statement(struct sqlite_header_context *ctx, struct eth_schema *eths)
{
  sqlite3_stmt *res = NULL;
  int column_idx, rc;

  if (eths == NULL) {
    log_trace("ethh is NULL");
    return -1;
  }

  rc = sqlite3_prepare_v2(ctx->db, ETH_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    if (sqlite3_bind_int64(res, column_idx, eths->hash) != SQLITE_OK)
      return false;

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    if(sqlite3_bind_int64(res, column_idx, eths->timestamp) != SQLITE_OK)
      return false;

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, eths->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@caplen");
    if (sqlite3_bind_int64(res, column_idx, eths->caplen) != SQLITE_OK)
      return false;

    column_idx = sqlite3_bind_parameter_index(res, "@length");
    if (sqlite3_bind_int64(res, column_idx, eths->length) != SQLITE_OK)
      return false;

    column_idx = sqlite3_bind_parameter_index(res, "@ifname");
    sqlite3_bind_text(res, column_idx, eths->ifname, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@hostname");
    sqlite3_bind_text(res, column_idx, eths->hostname, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ether_dhost");
    sqlite3_bind_text(res, column_idx, eths->ether_dhost, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ether_shost");
    sqlite3_bind_text(res, column_idx, eths->ether_shost, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ether_type");
    sqlite3_bind_int64(res, column_idx, eths->ether_type);

    log_trace("sqlite insert eth ether_type=0x%x ether_dhost=%s ether_shost=%s", eths->ether_type, eths->ether_dhost, eths->ether_shost);

    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_arp_statement(struct sqlite_header_context *ctx, struct arp_schema *arps)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, ARP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, arps->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, arps->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, arps->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, arps->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ar_hrd");
    sqlite3_bind_int64(res, column_idx, arps->ar_hrd);

    column_idx = sqlite3_bind_parameter_index(res, "@ar_pro");
    sqlite3_bind_int64(res, column_idx, arps->ar_pro);

    column_idx = sqlite3_bind_parameter_index(res, "@ar_hln");
    sqlite3_bind_int64(res, column_idx, arps->ar_hln);

    column_idx = sqlite3_bind_parameter_index(res, "@ar_pln");
    sqlite3_bind_int64(res, column_idx, arps->ar_pln);

    column_idx = sqlite3_bind_parameter_index(res, "@ar_op");
    sqlite3_bind_int64(res, column_idx, arps->ar_op);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_sha");
    sqlite3_bind_text(res, column_idx, arps->arp_sha, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_spa");
    sqlite3_bind_text(res, column_idx, arps->arp_spa, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_tha");
    sqlite3_bind_text(res, column_idx, arps->arp_tha, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@arp_tpa");
    sqlite3_bind_text(res, column_idx, arps->arp_tpa, -1, NULL);

    log_trace("sqlite insert arp ar_hrd=%d arp_sha=%s arp_spa=%s arp_tha=%s arp_tpa=%s",
      arps->ar_hrd, arps->arp_sha, arps->arp_spa, arps->arp_tha, arps->arp_tpa);

    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_trace("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_ip4_statement(struct sqlite_header_context *ctx, struct ip4_schema *ip4s)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;

  rc = sqlite3_prepare_v2(ctx->db, IP4_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, ip4s->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, ip4s->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, ip4s->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, ip4s->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_hl");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_hl);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_v");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_v);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_tos");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_tos);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_len");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_len);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_id");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_id);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_off");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_off);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_ttl");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_ttl);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_p");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_p);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_sum");
    sqlite3_bind_int64(res, column_idx, ip4s->ip_sum);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_src");
    sqlite3_bind_text(res, column_idx, ip4s->ip_src, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ip_dst");
    sqlite3_bind_text(res, column_idx, ip4s->ip_dst, -1, NULL);

    log_trace("sqlite insert IP4 ip_p=%d ip_v=%d ip_src=%s ip_dst=%s", ip4s->ip_p, ip4s->ip_v, ip4s->ip_src, ip4s->ip_dst);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_ip6_statement(struct sqlite_header_context *ctx, struct ip6_schema *ip6s)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, IP6_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, ip6s->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, ip6s->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, ip6s->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, ip6s->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_flow");
    sqlite3_bind_int64(res, column_idx, ip6s->ip6_un1_flow);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_plen");
    sqlite3_bind_int64(res, column_idx, ip6s->ip6_un1_plen);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_nxt");
    sqlite3_bind_int64(res, column_idx, ip6s->ip6_un1_nxt);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un1_hlim");
    sqlite3_bind_int64(res, column_idx, ip6s->ip6_un1_hlim);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_un2_vfc");
    sqlite3_bind_int64(res, column_idx, ip6s->ip6_un2_vfc);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_src");
    sqlite3_bind_text(res, column_idx, ip6s->ip6_src, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@ip6_dst");
    sqlite3_bind_text(res, column_idx, ip6s->ip6_dst, -1, NULL);

    log_trace("sqlite insert IP6 ip6_src=%s ip6_dst=%s ip6_un1_nxt=%d",
      ip6s->ip6_src, ip6s->ip6_dst, ip6s->ip6_un1_nxt);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_tcp_statement(struct sqlite_header_context *ctx, struct tcp_schema *tcps)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, TCP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, tcps->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, tcps->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, tcps->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, tcps->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@source");
    sqlite3_bind_int64(res, column_idx, tcps->source);

    column_idx = sqlite3_bind_parameter_index(res, "@dest");
    sqlite3_bind_int64(res, column_idx, tcps->dest);

    column_idx = sqlite3_bind_parameter_index(res, "@seq");
    sqlite3_bind_int64(res, column_idx, tcps->seq);

    column_idx = sqlite3_bind_parameter_index(res, "@ack_seq");
    sqlite3_bind_int64(res, column_idx, tcps->ack_seq);

    column_idx = sqlite3_bind_parameter_index(res, "@res1");
    sqlite3_bind_int64(res, column_idx, tcps->res1);

    column_idx = sqlite3_bind_parameter_index(res, "@doff");
    sqlite3_bind_int64(res, column_idx, tcps->doff);

    column_idx = sqlite3_bind_parameter_index(res, "@fin");
    sqlite3_bind_int64(res, column_idx, tcps->fin);

    column_idx = sqlite3_bind_parameter_index(res, "@syn");
    sqlite3_bind_int64(res, column_idx, tcps->syn);

    column_idx = sqlite3_bind_parameter_index(res, "@rst");
    sqlite3_bind_int64(res, column_idx, tcps->rst);

    column_idx = sqlite3_bind_parameter_index(res, "@psh");
    sqlite3_bind_int64(res, column_idx, tcps->psh);

    column_idx = sqlite3_bind_parameter_index(res, "@ack");
    sqlite3_bind_int64(res, column_idx, tcps->ack);

    column_idx = sqlite3_bind_parameter_index(res, "@urg");
    sqlite3_bind_int64(res, column_idx, tcps->urg);

    column_idx = sqlite3_bind_parameter_index(res, "@window");
    sqlite3_bind_int64(res, column_idx, tcps->window);

    column_idx = sqlite3_bind_parameter_index(res, "@check_p");
    sqlite3_bind_int64(res, column_idx, tcps->check_p);

    column_idx = sqlite3_bind_parameter_index(res, "@urg_ptr");
    sqlite3_bind_int64(res, column_idx, tcps->urg_ptr);

    log_trace("sqlite insert TCP source=%d dest=%d", tcps->source, tcps->dest);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_udp_statement(struct sqlite_header_context *ctx, struct udp_schema *udps)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, UDP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, udps->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, udps->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, udps->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, udps->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@source");
    sqlite3_bind_int64(res, column_idx, udps->source);

    column_idx = sqlite3_bind_parameter_index(res, "@dest");
    sqlite3_bind_int64(res, column_idx, udps->dest);

    column_idx = sqlite3_bind_parameter_index(res, "@len");
    sqlite3_bind_int64(res, column_idx, udps->len);

    column_idx = sqlite3_bind_parameter_index(res, "@check_p");
    sqlite3_bind_int64(res, column_idx, udps->check_p);

    log_trace("sqlite insert UDP source=%d dest=%d", udps->source, udps->dest);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_icmp4_statement(struct sqlite_header_context *ctx, struct icmp4_schema *icmp4s)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, ICMP4_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, icmp4s->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, icmp4s->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, icmp4s->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, icmp4s->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@type");
    sqlite3_bind_int64(res, column_idx, icmp4s->type);

    column_idx = sqlite3_bind_parameter_index(res, "@code");
    sqlite3_bind_int64(res, column_idx, icmp4s->code);

    column_idx = sqlite3_bind_parameter_index(res, "@checksum");
    sqlite3_bind_int64(res, column_idx, icmp4s->checksum);

    column_idx = sqlite3_bind_parameter_index(res, "@gateway");
    sqlite3_bind_int64(res, column_idx, icmp4s->gateway);

    log_trace("sqlite insert ICMP4 type=%d code=%d", icmp4s->type, icmp4s->code);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_icmp6_statement(struct sqlite_header_context *ctx, struct icmp6_schema *icmp6s)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, ICMP6_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, icmp6s->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, icmp6s->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, icmp6s->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, icmp6s->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_type");
    sqlite3_bind_int64(res, column_idx, icmp6s->icmp6_type);

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_code");
    sqlite3_bind_int64(res, column_idx, icmp6s->icmp6_code);

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_cksum");
    sqlite3_bind_int64(res, column_idx, icmp6s->icmp6_cksum);

    column_idx = sqlite3_bind_parameter_index(res, "@icmp6_un_data32");
    sqlite3_bind_int64(res, column_idx, icmp6s->icmp6_un_data32);

    log_trace("sqlite insert ICMP6 type=%d code=%d", icmp6s->icmp6_type, icmp6s->icmp6_code);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_dns_statement(struct sqlite_header_context *ctx, struct dns_schema *dnss)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, DNS_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, dnss->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, dnss->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, dnss->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, dnss->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@tid");
    sqlite3_bind_int64(res, column_idx, dnss->tid);

    column_idx = sqlite3_bind_parameter_index(res, "@flags");
    sqlite3_bind_int64(res, column_idx, dnss->flags);

    column_idx = sqlite3_bind_parameter_index(res, "@nqueries");
    sqlite3_bind_int64(res, column_idx, dnss->nqueries);

    column_idx = sqlite3_bind_parameter_index(res, "@nanswers");
    sqlite3_bind_int64(res, column_idx, dnss->nanswers);

    column_idx = sqlite3_bind_parameter_index(res, "@nauth");
    sqlite3_bind_int64(res, column_idx, dnss->nauth);

    column_idx = sqlite3_bind_parameter_index(res, "@nother");
    sqlite3_bind_int64(res, column_idx, dnss->nother);

    column_idx = sqlite3_bind_parameter_index(res, "@qname");
    sqlite3_bind_text(res, column_idx, dnss->qname, -1, NULL);

    log_trace("sqlite insert DNS tid=%d, qname=%s", dnss->tid, dnss->qname);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_mdsn_statement(struct sqlite_header_context *ctx, struct mdns_schema *mdnss)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;

  rc = sqlite3_prepare_v2(ctx->db, MDNS_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, mdnss->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, mdnss->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, mdnss->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, mdnss->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@tid");
    sqlite3_bind_int64(res, column_idx, mdnss->tid);

    column_idx = sqlite3_bind_parameter_index(res, "@flags");
    sqlite3_bind_int64(res, column_idx, mdnss->flags);

    column_idx = sqlite3_bind_parameter_index(res, "@nqueries");
    sqlite3_bind_int64(res, column_idx, mdnss->nqueries);

    column_idx = sqlite3_bind_parameter_index(res, "@nanswers");
    sqlite3_bind_int64(res, column_idx, mdnss->nanswers);

    column_idx = sqlite3_bind_parameter_index(res, "@nauth");
    sqlite3_bind_int64(res, column_idx, mdnss->nauth);

    column_idx = sqlite3_bind_parameter_index(res, "@nother");
    sqlite3_bind_int64(res, column_idx, mdnss->nother);

    column_idx = sqlite3_bind_parameter_index(res, "@qname");
    sqlite3_bind_text(res, column_idx, mdnss->qname, -1, NULL);

    log_trace("sqlite insert mDNS tid=%d, qname=%s", mdnss->tid, mdnss->qname);

    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int extract_dhcp_statement(struct sqlite_header_context *ctx, struct dhcp_schema *dhcps)
{
  int column_idx, rc;
  sqlite3_stmt *res = NULL;
  
  rc = sqlite3_prepare_v2(ctx->db, DHCP_INSERT_INTO, -1, &res, 0);

  if (rc == SQLITE_OK) {
    column_idx = sqlite3_bind_parameter_index(res, "@hash");
    sqlite3_bind_int64(res, column_idx, dhcps->hash);

    column_idx = sqlite3_bind_parameter_index(res, "@timestamp");
    sqlite3_bind_int64(res, column_idx, dhcps->timestamp);

    column_idx = sqlite3_bind_parameter_index(res, "@ethh_hash");
    sqlite3_bind_int64(res, column_idx, dhcps->ethh_hash);

    column_idx = sqlite3_bind_parameter_index(res, "@id");
    sqlite3_bind_text(res, column_idx, dhcps->id, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@op");
    sqlite3_bind_int64(res, column_idx, dhcps->op);

    column_idx = sqlite3_bind_parameter_index(res, "@htype");
    sqlite3_bind_int64(res, column_idx, dhcps->htype);

    column_idx = sqlite3_bind_parameter_index(res, "@hlen");
    sqlite3_bind_int64(res, column_idx, dhcps->hlen);

    column_idx = sqlite3_bind_parameter_index(res, "@hops");
    sqlite3_bind_int64(res, column_idx, dhcps->hops);

    column_idx = sqlite3_bind_parameter_index(res, "@xid");
    sqlite3_bind_int64(res, column_idx, dhcps->xid);

    column_idx = sqlite3_bind_parameter_index(res, "@secs");
    sqlite3_bind_int64(res, column_idx, dhcps->secs);

    column_idx = sqlite3_bind_parameter_index(res, "@flags");
    sqlite3_bind_int64(res, column_idx, dhcps->flags);

    column_idx = sqlite3_bind_parameter_index(res, "@ciaddr");
    sqlite3_bind_text(res, column_idx, dhcps->ciaddr, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@yiaddr");
    sqlite3_bind_text(res, column_idx, dhcps->yiaddr, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@siaddr");
    sqlite3_bind_text(res, column_idx, dhcps->siaddr, -1, NULL);

    column_idx = sqlite3_bind_parameter_index(res, "@giaddr");
    sqlite3_bind_text(res, column_idx, dhcps->giaddr, -1, NULL);

    log_trace("sqlite insert DHCP ciaddr=%s yiaddr=%s siaddr=%s giaddr=%s",
      dhcps->ciaddr, dhcps->yiaddr, dhcps->siaddr, dhcps->giaddr);
    sqlite3_step(res);
    sqlite3_finalize(res);
  } else {
    log_debug("Failed to prepare statement: %s", sqlite3_errmsg(ctx->db));
    return -1;
  }

  return 0;
}

int save_packet_statement(struct sqlite_header_context *ctx, struct tuple_packet *tp)
{
  if (tp == NULL) {
    log_trace("tp param is NULL");
    return -1;
  }

  if (tp->packet == NULL) {
    log_trace("tp->packet param is NULL");
    return -1;
  }

  switch (tp->type) {
    case PACKET_NONE:
      return -1;
    case PACKET_ETHERNET:
      return extract_eth_statement(ctx, (struct eth_schema *)tp->packet);
    case PACKET_ARP:
      return extract_arp_statement(ctx, (struct arp_schema *)tp->packet);
    case PACKET_IP4:
      return extract_ip4_statement(ctx, (struct ip4_schema *)tp->packet);
    case PACKET_IP6:
      return extract_ip6_statement(ctx, (struct ip6_schema *)tp->packet);
    case PACKET_TCP:
      return extract_tcp_statement(ctx, (struct tcp_schema *)tp->packet);
    case PACKET_UDP:
      return extract_udp_statement(ctx, (struct udp_schema *)tp->packet);
    case PACKET_ICMP4:
      return extract_icmp4_statement(ctx, (struct icmp4_schema *)tp->packet);
    case PACKET_ICMP6:
      return extract_icmp6_statement(ctx, (struct icmp6_schema *)tp->packet);
    case PACKET_DNS:
      return extract_dns_statement(ctx, (struct dns_schema *)tp->packet);
    case PACKET_MDNS:
      return extract_mdsn_statement(ctx, (struct mdns_schema *)tp->packet);
    case PACKET_DHCP:
      return extract_dhcp_statement(ctx, (struct dhcp_schema *)tp->packet);
  }

  return -1;
}

void free_sqlite_header_db(struct sqlite_header_context *ctx)
{
  if (ctx != NULL) {
    if (ctx->db != NULL)
      sqlite3_close(ctx->db);
    os_free(ctx);
  }
}

int sqlite_trace_callback(unsigned int uMask, void* ctx, void* stm, void* X)
{
  (void) uMask;
  (void) X;

  struct sqlite_header_context *sql_ctx = (struct sqlite_header_context *)ctx;
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
                               void *trace_ctx, struct sqlite_header_context **ctx)
{
  
  sqlite3 *db;
  struct sqlite_header_context *context = NULL;

  int rc = sqlite3_open(db_path, &db);

  if (rc != SQLITE_OK) {
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  context = os_zalloc(sizeof(struct sqlite_header_context));
  context->db = db;
  context->trace_fn = fn;
  context->trace_ctx = trace_ctx;
  *ctx = context;

  if (context->trace_fn != NULL) {
    log_trace("Register sqlite trace callback");
    sqlite3_trace_v2(db, SQLITE_TRACE_STMT, sqlite_trace_callback, (void *)context);
  }

  log_debug("sqlite autocommit mode=%d", sqlite3_get_autocommit(db));

  rc = check_table_exists(db, "eth");

  if (rc == 0) {
    log_debug("eth table doesn't exist creating...");
    if (execute_sqlite_query(db, ETH_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "arp");

  if (rc == 0) {
    log_debug("arp table doesn't exist creating...");
    if (execute_sqlite_query(db, ARP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "ip4");

  if (rc == 0) {
    log_debug("ip4 table doesn't exist creating...");
    if (execute_sqlite_query(db, IP4_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "ip6");

  if (rc == 0) {
    log_debug("ip6 table doesn't exist creating...");
    if (execute_sqlite_query(db, IP6_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "tcp");

  if (rc == 0) {
    log_debug("tcp table doesn't exist creating...");
    if (execute_sqlite_query(db, TCP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "udp");

  if (rc == 0) {
    log_debug("udp table doesn't exist creating...");
    if (execute_sqlite_query(db, UDP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "icmp4");

  if (rc == 0) {
    log_debug("icmp4 table doesn't exist creating...");
    if (execute_sqlite_query(db, ICMP4_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "icmp6");

  if (rc == 0) {
    log_debug("icmp6 table doesn't exist creating...");
    if (execute_sqlite_query(db, ICMP6_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "dns");

  if (rc == 0) {
    log_debug("dns table doesn't exist creating...");
    if (execute_sqlite_query(db, DNS_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "mdns");

  if (rc == 0) {
    log_debug("mdns table doesn't exist creating...");
    if (execute_sqlite_query(db, MDNS_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  rc = check_table_exists(db, "dhcp");

  if (rc == 0) {
    log_debug("dhcp table doesn't exist creating...");
    if (execute_sqlite_query(db, DHCP_CREATE_TABLE) < 0) {
      log_debug("execute_sqlite_query fail");
      free_sqlite_header_db(context);
      return -1;
    }
  } else if (rc < 0) {
    log_debug("check_table_exists fail");
    free_sqlite_header_db(context);
    return -1;
  }

  return 0;
}
