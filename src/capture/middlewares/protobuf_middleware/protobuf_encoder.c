/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the protobuf encoder utilities.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/log.h"
#include "../../../utils/allocs.h"
#include "../../../utils/os.h"

#include "../header_middleware/packet_decoder.h"

#include "eth.pb-c.h"
#include "arp.pb-c.h"
#include "ip4.pb-c.h"
#include "ip6.pb-c.h"
#include "tcp.pb-c.h"
#include "udp.pb-c.h"
#include "icmp4.pb-c.h"
#include "icmp6.pb-c.h"
#include "dns.pb-c.h"
#include "mdns.pb-c.h"
#include "dhcp.pb-c.h"

ssize_t encode_protobuf_packet(struct tuple_packet *tp, uint8_t **buffer) {
  (void)tp;
  (void)buffer;
  return -1;
}