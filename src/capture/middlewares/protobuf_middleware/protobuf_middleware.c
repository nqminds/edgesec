/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the protobuf middleware
 * utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <sqlite3.h>

#include "protobuf_middleware.h"

#include "../../../utils/allocs.h"
#include "../../../utils/os.h"
#include "../../../utils/log.h"
#include "../../../utils/squeue.h"
#include "../../../utils/eloop.h"

#include "../../pcap_service.h"

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

void free_protobuf_middleware(struct middleware_context *context) {
  (void) context;
}

struct middleware_context *init_protobuf_middleware(sqlite3 *db, char *db_path,
                                               struct eloop_data *eloop,
                                               struct pcap_context *pc,
                                               char *params) {
  (void)db;
  (void)db_path;
  (void)eloop;
  (void)pc;
  (void)params;

  return NULL;
}

int process_protobuf_middleware(struct middleware_context *context,
                           const char *ltype, struct pcap_pkthdr *header,
                           uint8_t *packet, char *ifname) {
  (void)context;
  (void)ltype;
  (void)header;
  (void)packet;
  (void)ifname;

  return 0;
}

struct capture_middleware protobuf_middleware = {
    .init = init_protobuf_middleware,
    .process = process_protobuf_middleware,
    .free = free_protobuf_middleware,
    .name = "protobuf middleware",
};
