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
 * @file ndpi_serialiser.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the ndpi serialiser utils.
 */

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

#include "ndpi_serialiser.h"

#include "../utils/log.h"
#include "../utils/os.h"

int ndpi_serialise_dhcp(struct ndpi_flow_struct *flow, struct nDPI_flow_meta *meta)
{
  log_trace("dhcp_fingerprint=%s", flow->protos.dhcp.fingerprint);
  log_trace("dhcp_class_ident=%s", flow->protos.dhcp.class_ident);
  return 1;
}

int ndpi_serialise_dns(struct ndpi_flow_struct *flow, struct nDPI_flow_meta *meta)
{
  char dns_rsp_addr[64];

  if (inet_ntop(AF_INET, &flow->protos.dns.rsp_addr, dns_rsp_addr, sizeof(dns_rsp_addr)) == NULL) {
    log_err("inet_ntop");
    return -1;
  }

  log_trace("dns_num_queries=%u", flow->protos.dns.num_queries);
  log_trace("dns_num_answers=%u", flow->protos.dns.num_answers);
  log_trace("dns_reply_code=%u", flow->protos.dns.reply_code);
  log_trace("dns_query_type=%u", flow->protos.dns.query_type);
  log_trace("dns_rsp_type=%u", flow->protos.dns.query_type);
  log_trace("dns_rsp_addr=%s", dns_rsp_addr);

  size_t str_len = os_strnlen_s(flow->host_server_name, sizeof(flow->host_server_name));
  if(str_len > 0 && str_len < sizeof(flow->host_server_name)) {
    log_trace("dns_query=%s", flow->host_server_name);
    sha256_hash(meta->hash, flow->host_server_name, strlen(flow->host_server_name));
    return 0;
  } else {
    log_trace("Malformed host_server_name");
    return -1;
  }
}

int ndpi_serialise_mdns(struct ndpi_flow_struct *flow, struct nDPI_flow_meta *meta)
{
  size_t str_len = os_strnlen_s(flow->host_server_name, sizeof(flow->host_server_name));
  if(str_len > 0 && str_len < sizeof(flow->host_server_name)) {
    log_trace("mdns_query=%s", flow->host_server_name);
    sha256_hash(meta->hash, flow->host_server_name, strlen(flow->host_server_name));
    return 0;
  } else {
    log_trace("Malformed host_server_name");
    return -1;
  }
}

int ndpi_serialise_meta(struct ndpi_detection_module_struct *ndpi_struct,
		  struct nDPI_flow_info * flow_info, struct nDPI_flow_meta *meta)
{
  char *breed_name = NULL;
  char *category_name = NULL;
  struct ndpi_flow_struct *flow = flow_info->ndpi_flow;

  struct ndpi_proto l7_protocol = flow_info->detected_l7_protocol;

  ndpi_protocol2name(ndpi_struct, l7_protocol, meta->protocol, sizeof(meta->protocol));

  os_memcpy(meta->src_mac_addr, flow_info->h_source, ETH_ALEN);
  os_memcpy(meta->dst_mac_addr, flow_info->h_dest, ETH_ALEN);

  ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_struct,
                           (l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN ? l7_protocol.app_protocol : l7_protocol.master_protocol));
  breed_name = ndpi_get_proto_breed_name(ndpi_struct, breed);
  
  if(l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    category_name = (char *)ndpi_category_get_name(ndpi_struct, l7_protocol.category);

  log_trace("proto=%s", meta->protocol);
  log_trace("breed=%s", breed_name);
  log_trace("category=%s", category_name);
  log_trace("source=" MACSTR " dest=" MACSTR, MAC2STR(flow_info->h_source), MAC2STR(flow_info->h_dest));

  switch(l7_protocol.master_protocol ? l7_protocol.master_protocol : l7_protocol.app_protocol) {
    case NDPI_PROTOCOL_DHCP:
      return ndpi_serialise_dhcp(flow, meta);

    case NDPI_PROTOCOL_BITTORRENT:
      break;

    case NDPI_PROTOCOL_DNS:
      return ndpi_serialise_dns(flow, meta);

    case NDPI_PROTOCOL_MDNS:
      return ndpi_serialise_mdns(flow, meta);

    case NDPI_PROTOCOL_UBNTAC2:
      break;
    case NDPI_PROTOCOL_KERBEROS:
      break;
    case NDPI_PROTOCOL_TELNET:
      break;
    case NDPI_PROTOCOL_HTTP:
      break;
    case NDPI_PROTOCOL_QUIC:
      break;
    case NDPI_PROTOCOL_MAIL_IMAP:
      break;
    case NDPI_PROTOCOL_MAIL_POP:
      break;
    case NDPI_PROTOCOL_MAIL_SMTP:
      break;
    case NDPI_PROTOCOL_FTP_CONTROL:
      break;
    case NDPI_PROTOCOL_SSH:
      break;
    case NDPI_PROTOCOL_TLS:
      if(flow->protos.stun_ssl.ssl.ssl_version) {
        char notBefore[32], notAfter[32];
        char certificate_fingerprint[64];
        struct tm a, b, *before = NULL, *after = NULL;
        uint16_t i, off;
        uint8_t unknown_tls_version;

        os_memset(notBefore, 0, 32);
        os_memset(notAfter, 0, 32);
        char *version = ndpi_ssl_version2str(flow, flow->protos.stun_ssl.ssl.ssl_version, &unknown_tls_version);
        char *client_requested_server_name = NULL;
        char *server_names = NULL;
        char *ja3 = NULL;
        char *ja3s = NULL;
        char *cipher = NULL;
        char *issuerDN = NULL;
        char *subjectDN = NULL;
        char *alpn = NULL;
        char *tls_supported_versions = NULL;
        uint32_t unsafe_cipher;

        if(flow->protos.stun_ssl.ssl.notBefore) {
          before = gmtime_r((const time_t *)&flow->protos.stun_ssl.ssl.notBefore, &a);
        }

        if(flow->protos.stun_ssl.ssl.notAfter) {
          after  = gmtime_r((const time_t *)&flow->protos.stun_ssl.ssl.notAfter, &b);
        }

        if(!unknown_tls_version) {
	        client_requested_server_name = flow->protos.stun_ssl.ssl.client_requested_server_name;
	        if(flow->protos.stun_ssl.ssl.server_names)
	          server_names = flow->protos.stun_ssl.ssl.server_names;

	        if(before) {
            strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
          }

	        if(after) {
	          strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);
          }

	        ja3 = flow->protos.stun_ssl.ssl.ja3_client;
	        ja3s = flow->protos.stun_ssl.ssl.ja3_server;
	        unsafe_cipher = flow->protos.stun_ssl.ssl.server_unsafe_cipher;
	        cipher = (char *)ndpi_cipher2str(flow->protos.stun_ssl.ssl.server_cipher);

	        if(flow->protos.stun_ssl.ssl.issuerDN)
	          issuerDN = flow->protos.stun_ssl.ssl.issuerDN;

	        if(flow->protos.stun_ssl.ssl.subjectDN)
	          subjectDN = flow->protos.stun_ssl.ssl.subjectDN;

	        if(flow->protos.stun_ssl.ssl.alpn)
	          alpn = flow->protos.stun_ssl.ssl.alpn;

	        if(flow->protos.stun_ssl.ssl.tls_supported_versions)
	          tls_supported_versions = flow->protos.stun_ssl.ssl.tls_supported_versions;

          log_trace("version=%s", version);
          log_trace("client_requested_server_name=%s", client_requested_server_name);
          log_trace("server_names=%s", server_names);
          log_trace("notBefore=%s", notBefore);
          log_trace("notAfter=%s", notAfter);
          log_trace("ja3=%s", ja3);
          log_trace("ja3s=%s", ja3s);
          log_trace("unsafe_cipher=%u", unsafe_cipher);
          log_trace("cipher=%s", cipher);
          log_trace("esni=%s", flow->protos.stun_ssl.ssl.encrypted_sni.esni);
          log_trace("issuerDN=%s", issuerDN);
          log_trace("subjectDN=%s", subjectDN);
          log_trace("alpn=%s", alpn);
          log_trace("tls_supported_versions=%s", tls_supported_versions);
          log_trace("hello_processed=%d", flow->l4.tcp.tls.hello_processed);
          log_trace("certificate_processed=%d", flow->l4.tcp.tls.certificate_processed);
          log_trace("fingerprint_set=%d", flow->l4.tcp.tls.fingerprint_set);
          if (flow->l4.tcp.tls.sha1_certificate_fingerprint[0] != '\0') {
	          for(i=0, off=0; i<20; i++) {
	            int rc = snprintf(&certificate_fingerprint[off], sizeof(certificate_fingerprint) - off, "%s%02X", (i > 0) ? ":" : "",
		        	      flow->l4.tcp.tls.sha1_certificate_fingerprint[i] & 0xFF);

	            if(rc <= 0) break; else off += rc;
	          }
            log_trace("certificate_fingerprint=%s", certificate_fingerprint);
          }
        }
      }
      break;
  }

  return 1;
}
