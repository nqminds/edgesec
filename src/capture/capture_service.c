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
#include "../utils/if.h"
#include "../utils/log.h"

bool find_device(char *ifname, bpf_u_int32 *net, bpf_u_int32 *mask)
{
  pcap_if_t *temp = NULL, *ifs = NULL;
  char err[PCAP_ERRBUF_SIZE];

  if (ifname == NULL) {
    log_trace("ifname is NULL");
    return false;
  }

  if(pcap_findalldevs(&ifs, err) == -1) {
    log_trace("pcap_findalldevs fail with error %s", err);
    return false;   
  }

  for(temp = ifs; temp; temp = temp->next) {
    log_trace("Checking interface %s (%s)", temp->name, temp->description);
    if (strcmp(temp->name, ifname) == 0) {
	    if (pcap_lookupnet(ifname, net, mask, err) == -1) {
		    log_trace("Can't get netmask for device %s\n", ifname);
        return false;
	    }

      pcap_freealldevs(ifs);
      return true;
    }
  }

  pcap_freealldevs(ifs);
  return false;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  // log_trace("timestamp=%llu caplen=%lu len=%lu", packet_timestamp, packet_caplen, packet_len);
  decode_packet(header, packet);
}

int run_capture(struct capture_conf *config)
{
	int ret;
  pcap_t *handle;
  char err[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask, net;
  char *net_str, *mask_str;

  log_info("Capturing interface %s", config->capture_interface);
  log_info("Promiscuous mode=%d", config->promiscuous);
  log_info("Buffer timeout=%d", config->buffer_timeout);

  if (!find_device(config->capture_interface, &net, &mask)) {
    log_trace("find_interfaces fail");
    return -1;
  }

  net_str = bit32_2_ip((uint32_t) net);
  mask_str = bit32_2_ip((uint32_t) mask);
  log_info("Found device=%s IP=%s netmask=%s", config->capture_interface, bit32_2_ip((uint32_t) net), bit32_2_ip((uint32_t) mask));
  os_free(net_str);
  os_free(mask_str);

	handle = pcap_open_live(config->capture_interface, BUFSIZ,
                          config->promiscuous, config->buffer_timeout, err);
	if (handle == NULL) {
	  log_trace("Couldn't open device %s: %s", config->capture_interface, err);
	  return -1;
	}

  log_info("Capture started on %s with link_type=%s", config->capture_interface,
            pcap_datalink_val_to_name(pcap_datalink(handle)));
  if ((ret = pcap_loop(handle, -1, got_packet, NULL)) < 0 ) {
    if (ret == -2) {
      log_trace("pcap_loop fail");
      pcap_close(handle);
      return -1;
    } else if (ret == -1) {
      log_trace("pcap_breakloop fail");
      pcap_close(handle);
      return 0;
    }
  } 
	/* And close the session */
	pcap_close(handle);
  log_info("Capture ended.");
  return 0;
}
