/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the packet decoder utilities.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "../../../utils/log.h"
#include "../../../utils/allocs.h"
#include "../../../utils/os.h"
#include "../../../utils/net.h"
#include "../../../utils/hash.h"
#include "../../../utils/utarray.h"

#include "packet_decoder.h"
#include "dns_decoder.h"
#include "mdns_decoder.h"

#define LINKTYPE_LINUX_SLL "LINUX_SLL"
#define LINKTYPE_ETHERNET "EN10MB"

/* Linux compat */
#ifndef IPV6_VERSION
#define IPV6_VERSION 0x60
#define IPV6_VERSION_MASK 0xf0
#endif /* IPV6_VERSION */

#define DNS_PORT 53
#define MDNS_PORT 5353
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define MAX_PACKET_TYPES 10

bool decode_dhcp_packet(struct capture_packet *cpac) {
  if ((void *)cpac->udph != NULL) {
    cpac->dhcph =
        (struct dhcp_header *)((void *)cpac->udph + sizeof(struct udphdr));
  } else
    return false;

  strcpy(cpac->dhcps.id, cpac->id);

  cpac->dhcps.op = cpac->dhcph->op;
  cpac->dhcps.htype = cpac->dhcph->htype;
  cpac->dhcps.hlen = cpac->dhcph->hlen;
  cpac->dhcps.hops = cpac->dhcph->hops;
  cpac->dhcps.xid = ntohl(cpac->dhcph->xid);
  cpac->dhcps.secs = ntohs(cpac->dhcph->secs);
  cpac->dhcps.flags = ntohs(cpac->dhcph->flags);

  bit32_2_ip(cpac->dhcph->ciaddr, cpac->dhcps.ciaddr);
  bit32_2_ip(cpac->dhcph->yiaddr, cpac->dhcps.yiaddr);
  bit32_2_ip(cpac->dhcph->siaddr, cpac->dhcps.siaddr);
  bit32_2_ip(cpac->dhcph->giaddr, cpac->dhcps.giaddr);

  return false;
}

bool decode_udp_packet(struct capture_packet *cpac) {
  if ((void *)cpac->ip4h != NULL && (void *)cpac->ip6h == NULL)
    cpac->udph = (struct udphdr *)((void *)cpac->ip4h + sizeof(struct ip));
  else if ((void *)cpac->ip4h == NULL && (void *)cpac->ip6h != NULL)
    cpac->udph = (struct udphdr *)((void *)cpac->ip6h + sizeof(struct ip6_hdr));
  else
    return false;

  strcpy(cpac->udps.id, cpac->id);

  cpac->udps.source = ntohs(cpac->udph->source);
  cpac->udps.dest = ntohs(cpac->udph->dest);
  cpac->udps.len = ntohs(cpac->udph->len);
  cpac->udps.check_p = ntohs(cpac->udph->check);

  // log_trace("UDP source=%d dest=%d", cpac->udps.source, cpac->udps.dest);

  return true;
}

bool decode_tcp_packet(struct capture_packet *cpac) {
  if ((void *)cpac->ip4h != NULL && (void *)cpac->ip6h == NULL)
    cpac->tcph = (struct tcphdr *)((void *)cpac->ip4h + sizeof(struct ip));
  else if ((void *)cpac->ip4h == NULL && (void *)cpac->ip6h != NULL)
    cpac->tcph = (struct tcphdr *)((void *)cpac->ip6h + sizeof(struct ip6_hdr));
  else
    return false;

  strcpy(cpac->tcps.id, cpac->id);

  cpac->tcps.source = ntohs(cpac->tcph->source);
  cpac->tcps.dest = ntohs(cpac->tcph->dest);
  cpac->tcps.seq = ntohl(cpac->tcph->seq);
  cpac->tcps.ack_seq = ntohl(cpac->tcph->ack_seq);
  cpac->tcps.res1 = ntohs(cpac->tcph->res1);
  cpac->tcps.doff = ntohs(cpac->tcph->doff);
  cpac->tcps.fin = ntohs(cpac->tcph->fin);
  cpac->tcps.syn = ntohs(cpac->tcph->syn);
  cpac->tcps.rst = ntohs(cpac->tcph->rst);
  cpac->tcps.psh = ntohs(cpac->tcph->psh);
  cpac->tcps.ack = ntohs(cpac->tcph->ack);
  cpac->tcps.urg = ntohs(cpac->tcph->urg);
  cpac->tcps.window = ntohs(cpac->tcph->window);
  cpac->tcps.check_p = ntohs(cpac->tcph->check);
  cpac->tcps.urg_ptr = ntohs(cpac->tcph->urg_ptr);

  // log_trace("TCP source=%d dest=%d", cpac->tcps.source, cpac->tcps.dest);
  return true;
}

bool decode_icmp4_packet(struct capture_packet *cpac) {
  cpac->icmp4h = (struct icmphdr *)((void *)cpac->ip4h + sizeof(struct ip));

  strcpy(cpac->icmp4s.id, cpac->id);

  cpac->icmp4s.type = cpac->icmp4h->type;
  cpac->icmp4s.code = cpac->icmp4h->code;
  cpac->icmp4s.checksum = ntohs(cpac->icmp4h->checksum);
  cpac->icmp4s.gateway = ntohl(cpac->icmp4h->un.gateway);

  // log_trace("ICMP4 type=%d code=%d", cpac->icmp4s.type, cpac->icmp4s.code);

  return true;
}

bool decode_icmp6_packet(struct capture_packet *cpac) {
  cpac->icmp6h =
      (struct icmp6_hdr *)((void *)cpac->ip6h + sizeof(struct ip6_hdr));

  strcpy(cpac->icmp6s.id, cpac->id);

  cpac->icmp6s.icmp6_type = cpac->icmp6h->icmp6_type;
  cpac->icmp6s.icmp6_code = cpac->icmp6h->icmp6_code;
  cpac->icmp6s.icmp6_cksum = ntohs(cpac->icmp6h->icmp6_cksum);
  cpac->icmp6s.icmp6_un_data32 =
      ntohl(cpac->icmp6h->icmp6_dataun.icmp6_un_data32[0]);

  // log_trace("ICMP6 type=%d code=%d", cpac->icmp6s.icmp6_type,
  // cpac->icmp6s.icmp6_code);

  return true;
}

bool decode_ip4_packet(struct capture_packet *cpac) {
  // Return false if the header is not of the right length
  if (cpac->length - sizeof(struct ether_header) < sizeof(struct ip)) {
    return false;
  }

  cpac->ip4h = (struct ip *)((void *)cpac->ethh + sizeof(struct ether_header));

  strcpy(cpac->ip4s.id, cpac->id);

  cpac->ip4s.ip_hl = cpac->ip4h->ip_hl;
  cpac->ip4s.ip_v = cpac->ip4h->ip_v;
  cpac->ip4s.ip_tos = cpac->ip4h->ip_tos;
  cpac->ip4s.ip_len = ntohs(cpac->ip4h->ip_len);
  cpac->ip4s.ip_id = ntohs(cpac->ip4h->ip_id);
  cpac->ip4s.ip_off = ntohs(cpac->ip4h->ip_off);
  cpac->ip4s.ip_ttl = cpac->ip4h->ip_ttl;
  cpac->ip4s.ip_p = cpac->ip4h->ip_p;
  cpac->ip4s.ip_sum = ntohs(cpac->ip4h->ip_sum);
  inaddr4_2_ip(&((cpac->ip4h)->ip_src), cpac->ip4s.ip_src);
  inaddr4_2_ip(&((cpac->ip4h)->ip_dst), cpac->ip4s.ip_dst);

  // log_trace("IP4 ip_src=%s ip_dst=%s ip_p=%d ip_v=%d", cpac->ip4s.ip_src,
  // cpac->ip4s.ip_dst, cpac->ip4s.ip_p, cpac->ip4s.ip_v);

  // Process futher packets only if IP is version 4
  return (cpac->ip4s.ip_v == 4);
}

bool decode_ip6_packet(struct capture_packet *cpac) {
  // Return false if the header is not of the right length
  if (cpac->length - sizeof(struct ether_header) < sizeof(struct ip6_hdr)) {
    return false;
  }

  cpac->ip6h =
      (struct ip6_hdr *)((void *)cpac->ethh + sizeof(struct ether_header));

  // Wrong IP6 version
  if (((cpac->ip6h)->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
    cpac->ip6h = NULL;
    return false;
  }

  strcpy(cpac->ip6s.id, cpac->id);

  cpac->ip6s.ip6_un1_flow = ntohl(cpac->ip6h->ip6_flow);
  cpac->ip6s.ip6_un1_plen = ntohs(cpac->ip6h->ip6_plen);
  cpac->ip6s.ip6_un1_nxt = cpac->ip6h->ip6_nxt;
  cpac->ip6s.ip6_un1_hlim = cpac->ip6h->ip6_hlim;
  cpac->ip6s.ip6_un2_vfc = cpac->ip6h->ip6_vfc;
  inaddr6_2_ip(&(cpac->ip6h->ip6_src), cpac->ip6s.ip6_src);
  inaddr6_2_ip(&(cpac->ip6h->ip6_dst), cpac->ip6s.ip6_dst);

  // log_trace("IP6 ip6_src=%s ip6_dst=%s", cpac->ip6s.ip6_src,
  // cpac->ip6s.ip6_dst);
  return true;
}

bool decode_arp_packet(struct capture_packet *cpac) {
  cpac->arph =
      (struct ether_arp *)((void *)cpac->ethh + sizeof(struct ether_header));

  strcpy(cpac->arps.id, cpac->id);

  cpac->arps.ar_hrd = ntohs(cpac->arph->arp_hrd);
  cpac->arps.ar_pro = ntohs(cpac->arph->arp_pro);
  cpac->arps.ar_hln = cpac->arph->arp_hln;
  cpac->arps.ar_pln = cpac->arph->arp_pln;
  cpac->arps.ar_op = ntohs(cpac->arph->arp_op);

  snprintf(cpac->arps.arp_sha, MACSTR_LEN, MACSTR,
           MAC2STR(cpac->arph->arp_sha));
  snprintf(cpac->arps.arp_spa, OS_INET_ADDRSTRLEN, IPSTR,
           IP2STR(cpac->arph->arp_spa));
  snprintf(cpac->arps.arp_tha, MACSTR_LEN, MACSTR,
           MAC2STR(cpac->arph->arp_tha));
  snprintf(cpac->arps.arp_tpa, OS_INET_ADDRSTRLEN, IPSTR,
           IP2STR(cpac->arph->arp_tpa));

  // log_trace("ARP arp_sha=" MACSTR " arp_spa=" IPSTR " arp_tha=" MACSTR,
  // MAC2STR((cpac->arph)->arp_sha), IP2STR((cpac->arph)->arp_spa),
  // MAC2STR((cpac->arph)->arp_tha));

  return true;
}

bool decode_eth_packet(const struct pcap_pkthdr *header, const uint8_t *packet,
                       struct capture_packet *cpac) {
  if (header->caplen >= sizeof(struct ether_header)) {
    cpac->ethh = (struct ether_header *)packet;

    // Init eth packet schema
    cpac->eths.timestamp = cpac->timestamp;
    strcpy(cpac->eths.id, cpac->id);
    strcpy(cpac->eths.ifname, cpac->ifname);
    cpac->eths.caplen = cpac->caplen;
    cpac->eths.length = cpac->length;

    snprintf(cpac->eths.ether_dhost, MACSTR_LEN, MACSTR,
             MAC2STR(cpac->ethh->ether_dhost));
    snprintf(cpac->eths.ether_shost, MACSTR_LEN, MACSTR,
             MAC2STR(cpac->ethh->ether_shost));
    cpac->eths.ether_type = ntohs(cpac->ethh->ether_type);

    // log_trace("Ethernet type=0x%x ether_dhost=%s ether_shost=%s ethh=0x%x",
    // cpac->eths.ether_type, cpac->eths.ether_dhost, cpac->eths.ether_shost,
    // cpac->ethh_hash);

    return true;
  }

  return false;
}

int decode_packet(const struct pcap_pkthdr *header, const uint8_t *packet,
                  struct capture_packet *cpac) {
  int count = 0;

  if (decode_eth_packet(header, packet, cpac)) {
    count = 1;
    if (cpac->eths.ether_type == ETHERTYPE_IP) {
      if (decode_ip4_packet(cpac)) {
        count++;
        if ((cpac->ip4h)->ip_p == IPPROTO_TCP) {
          if (decode_tcp_packet(cpac))
            count++;
        } else if ((cpac->ip4h)->ip_p == IPPROTO_UDP) {
          if (decode_udp_packet(cpac))
            count++;
        } else if ((cpac->ip4h)->ip_p == IPPROTO_ICMP) {
          if (decode_icmp4_packet(cpac))
            count++;
        }
      }
    } else if (cpac->eths.ether_type == ETHERTYPE_IPV6) {
      if (decode_ip6_packet(cpac)) {
        count++;
        if ((cpac->ip6h)->ip6_nxt == IPPROTO_TCP) {
          if (decode_tcp_packet(cpac))
            count++;
        } else if ((cpac->ip6h)->ip6_nxt == IPPROTO_UDP) {
          if (decode_udp_packet(cpac))
            count++;
        } else if ((cpac->ip6h)->ip6_nxt == IPPROTO_ICMPV6) {
          if (decode_icmp6_packet(cpac))
            count++;
        }
      }
    } else if (cpac->eths.ether_type == ETHERTYPE_ARP) {
      if (decode_arp_packet(cpac))
        count++;
    }

    if ((void *)cpac->tcph != NULL) {
      if (ntohs((cpac->tcph)->th_sport) == DNS_PORT ||
          ntohs((cpac->tcph)->th_dport) == DNS_PORT) {
        if (decode_dns_packet(cpac))
          count++;
      } else if (ntohs((cpac->tcph)->th_sport) == MDNS_PORT ||
                 ntohs((cpac->tcph)->th_dport) == MDNS_PORT) {
        if (decode_mdns_packet(cpac))
          count++;
      }
    } else if ((void *)cpac->udph != NULL) {
      if (ntohs((cpac->udph)->uh_sport) == DNS_PORT ||
          ntohs((cpac->udph)->uh_dport) == DNS_PORT) {
        if (decode_dns_packet(cpac))
          count++;
      } else if (ntohs((cpac->udph)->uh_sport) == MDNS_PORT ||
                 ntohs((cpac->udph)->uh_dport) == MDNS_PORT) {
        if (decode_mdns_packet(cpac))
          count++;
      } else if ((ntohs((cpac->udph)->uh_sport) == DHCP_CLIENT_PORT &&
                  ntohs((cpac->udph)->uh_dport) == DHCP_SERVER_PORT) ||
                 (ntohs((cpac->udph)->uh_sport) == DHCP_SERVER_PORT &&
                  ntohs((cpac->udph)->uh_dport) == DHCP_CLIENT_PORT)) {
        if (decode_dhcp_packet(cpac))
          count++;
      }
    }
  }

  return count;
}

int extract_packets(char *ltype, const struct pcap_pkthdr *header,
                    const uint8_t *packet, char *interface, char *id,
                    UT_array *tp_array) {
  (void)ltype;

  struct capture_packet cpac;
  struct tuple_packet tp;
  int count;

  memset(&cpac, 0, sizeof(struct capture_packet));
  os_memset(&tp, 0, sizeof(struct tuple_packet));

  os_to_timestamp(header->ts, &cpac.timestamp);
  cpac.caplen = header->caplen;
  cpac.length = header->len;

  os_strlcpy(cpac.ifname, interface, IFNAMSIZ);
  os_strlcpy(cpac.id, id, MAX_RANDOM_UUID_LEN);

  if ((count = decode_packet(header, packet, &cpac)) > 0) {
    if (cpac.ethh != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct eth_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.eths, sizeof(struct eth_schema));
      tp.type = PACKET_ETHERNET;
      utarray_push_back(tp_array, &tp);
    }
    if (cpac.arph != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct arp_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.arps, sizeof(struct arp_schema));
      tp.type = PACKET_ARP;
      utarray_push_back(tp_array, &tp);
    }
    if (cpac.ip4h != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct ip4_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.ip4s, sizeof(struct ip4_schema));
      tp.type = PACKET_IP4;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.ip6h != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct ip6_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.ip6s, sizeof(struct ip6_schema));
      tp.type = PACKET_IP6;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.tcph != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct tcp_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.tcps, sizeof(struct tcp_schema));
      tp.type = PACKET_TCP;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.udph != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct udp_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.udps, sizeof(struct udp_schema));
      tp.type = PACKET_UDP;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.icmp4h != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct icmp4_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.icmp4s, sizeof(struct icmp4_schema));
      tp.type = PACKET_ICMP4;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.icmp6h != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct icmp6_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.icmp6s, sizeof(struct icmp6_schema));
      tp.type = PACKET_ICMP6;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.dnsh != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct dns_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.dnss, sizeof(struct dns_schema));
      tp.type = PACKET_DNS;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.mdnsh != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct mdns_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.mdnss, sizeof(struct mdns_schema));
      tp.type = PACKET_MDNS;
      utarray_push_back(tp_array, &tp);
    };
    if (cpac.dhcph != NULL) {
      if ((tp.packet = os_malloc(sizeof(struct dhcp_schema))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      os_memcpy(tp.packet, &cpac.dhcps, sizeof(struct dhcp_schema));
      tp.type = PACKET_DHCP;
      utarray_push_back(tp_array, &tp);
    };
  }

  return utarray_len(tp_array);
}
