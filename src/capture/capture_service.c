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
 * @file capture_service.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the capture service.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <pcap.h>

#include "capture_config.h"
#include "packet_decoder.h"
#include "packet_queue.h"
#include "sqlite_writer.h"
#include "../utils/if.h"
#include "../utils/log.h"
#include "../utils/eloop.h"
#include "../utils/list.h"

#define PCAP_SNAPSHOT_LENGTH  1500
#define PCAP_BUFFER_SIZE      64*1024

struct capture_context {
  uint32_t process_interval;
  pcap_t *pd;
  struct packet_queue *queue;
  struct sqlite_context *sctx;
};

bool find_device(char *ifname, bpf_u_int32 *net, bpf_u_int32 *mask)
{
  pcap_if_t *temp = NULL, *ifs = NULL;
  char err[PCAP_ERRBUF_SIZE];

  if (ifname == NULL) {
    log_debug("ifname is NULL");
    return false;
  }

  if(pcap_findalldevs(&ifs, err) == -1) {
    log_debug("pcap_findalldevs fail with error %s", err);
    return false;   
  }

  for(temp = ifs; temp; temp = temp->next) {
    log_debug("Checking interface %s (%s)", temp->name, temp->description);
    if (strcmp(temp->name, ifname) == 0) {
	    if (pcap_lookupnet(ifname, net, mask, err) == -1) {
		    log_debug("Can't get netmask for device %s\n", ifname);
        return false;
	    }

      pcap_freealldevs(ifs);
      return true;
    }
  }

  pcap_freealldevs(ifs);
  return false;
}

void add_packet_queue(UT_array *tp_array, int count, struct packet_queue *queue)
{
  struct tuple_packet *p = NULL;
  while((p = (struct tuple_packet *) utarray_next(tp_array, p)) != NULL) {
    if (push_packet_queue(queue, *p) == NULL) {
      // Free the packet if cannot be added to the queue
      free_packet_tuple(p);
    }
  }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  UT_array *tp_array;
  int count;
  struct capture_context *context = (struct capture_context *) args;
  

  if ((count = extract_packets(header, packet, &tp_array)) > 0) {
    add_packet_queue(tp_array, count, context->queue);
  }

  utarray_free(tp_array);
}

void eloop_read_fd_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  struct capture_context *context = (struct capture_context *) sock_ctx;
  if (pcap_dispatch(context->pd, -1, got_packet, (u_char *) sock_ctx) < 0) {
    log_debug("pcap_dispatch fail");
  }
}

void eloop_tout_handler(void *eloop_ctx, void *user_ctx)
{
  struct capture_context *context = (struct capture_context *) user_ctx;
  struct packet_queue *el;
  ssize_t count = 0;

  // Process all packets in the queue
  while(get_packet_queue_length(context->queue)) {
    if ((el = pop_packet_queue(context->queue)) != NULL) {
      extract_statements(context->sctx, &(el->tp));
      // Process packet
      free_packet_queue_el(el);
      count ++;
    }
  }

  if (eloop_register_timeout(0, context->process_interval, eloop_tout_handler, (void *)NULL, (void *)context) == -1) {
    log_debug("eloop_register_timeout fail");
  }
}

int run_capture(struct capture_conf *config)
{
	int ret, fd;
  char err[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask, net;
  char ip_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];
  struct capture_context context;

  log_info("Capturing interface %s", config->capture_interface);
  log_info("Promiscuous mode=%d", config->promiscuous);
  log_info("Immediate mode=%d", config->immediate);
  log_info("Buffer timeout=%d", config->buffer_timeout);
  log_info("Process interval=%d (milliseconds)", config->process_interval);
  log_info("DB path=%s", config->db);

  // Transform to microseconds
  context.process_interval = config->process_interval * 1000;

  context.queue = init_packet_queue();

  if (context.queue == NULL) {
    log_debug("init_packet_queue fail");
    return -1;
  }

  if (!find_device(config->capture_interface, &net, &mask)) {
    log_debug("find_interfaces fail");
    free_packet_queue(context.queue);
    return -1;
  }

  bit32_2_ip((uint32_t) net, ip_str);
  bit32_2_ip((uint32_t) mask, mask_str);
  log_info("Found device=%s IP=" IPSTR " netmask=" IPSTR, config->capture_interface, IP2STR(ip_str), IP2STR(mask_str));

	if ((context.pd = pcap_create(config->capture_interface, err)) == NULL) {
	  log_debug("Couldn't open device %s: %s", config->capture_interface, err);
    free_packet_queue(context.queue);
	  return -1;
	}

  if (pcap_set_snaplen(context.pd, PCAP_SNAPSHOT_LENGTH) < 0) {
    log_debug("pcap_set_snaplen fail %d", ret);
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  if ((ret = pcap_set_immediate_mode(context.pd, 0)) < 0) {
    log_debug("pcap_set_immediate_mode fail %d", ret);
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  if ((ret = pcap_set_promisc(context.pd, config->promiscuous)) < 0) {
    log_debug("pcap_set_promisc fail: %d", ret);
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  if ((ret = pcap_set_timeout(context.pd, (int)config->buffer_timeout)) < 0) {
    log_debug("pcap_set_timeout fail: %d", ret);
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  if ((ret = pcap_set_buffer_size(context.pd, PCAP_BUFFER_SIZE)) < 0) {
    log_debug("pcap_set_buffer_size fail: %d", ret);
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  ret = pcap_activate(context.pd);

  if(ret < 0) {
    log_debug("pcap_activate fail: %d", ret);
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  } else if (ret > 0) {
    log_warn("pcap_activate %d", ret);
  }

  if ((fd = pcap_get_selectable_fd(context.pd)) == -1) {
    log_debug("pcap device doesn't support file descriptors");
	  /* And close the session */
	  pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  log_info("Capture started on %s with link_type=%s", config->capture_interface,
            pcap_datalink_val_to_name(pcap_datalink(context.pd)));

  if (pcap_setnonblock(context.pd, 1, err) < 0) {
    log_debug("pcap_setnonblock fail: %s", err);
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  log_info("Non-blocking state %d", pcap_getnonblock(context.pd, err));

  context.sctx = open_sqlite_db(config->db);

  if (context.sctx == NULL) {
    log_debug("open_sqlite_db fail");
    pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
  }

  if (eloop_init()) {
		log_debug("Failed to initialize event loop");
		pcap_close(context.pd);
    free_packet_queue(context.queue);
    return -1;
	}

  if (eloop_register_read_sock(fd, eloop_read_fd_handler, (void*)NULL, (void *)&context) ==  -1) {
    log_debug("eloop_register_read_sock fail");
    goto fail;
  }

  if (eloop_register_timeout(0, context.process_interval, eloop_tout_handler, (void *)NULL, (void *)&context) == -1) {
    log_debug("eloop_register_timeout fail");
    goto fail;
  }

  eloop_run();
  log_info("Capture ended.");

	/* And close the session */
	pcap_close(context.pd);
  eloop_destroy();
  free_packet_queue(context.queue);
  free_sqlite_db(context.sctx);
  return 0;

fail:
	pcap_close(context.pd);
  eloop_destroy();
  free_packet_queue(context.queue);
  free_sqlite_db(context.sctx);
  return -1;
}
