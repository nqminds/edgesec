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
 * @file packet_decoder.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the packet decoder utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

#include "../utils/log.h"
#include "../utils/os.h"

int decode_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ether_header* eth_hdr = (struct ether_header*) packet;
  uint64_t packet_timestamp = os_get_timestamp(header->ts);
  uint32_t packet_caplen = header->caplen;
  uint32_t packet_len = header->len;

  log_trace("Packet type=0x%x ether_dhost=" MACSTR, ntohs(eth_hdr->ether_type), MAC2STR(eth_hdr->ether_dhost));
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
    log_trace("Found IP packet");
  } else {
    log_trace("Found other packet");
  }
  return 0;
}