/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the pcap service utilities.
 */
#include <pcap.h>

#include "pcap_service.h"

#include "../utils/net.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/log.h"

#define PCAP_SNAPSHOT_LENGTH 65535
#define PCAP_BUFFER_SIZE 64 * 1024

static const UT_icd pcap_list_icd = {sizeof(struct pcap_context *), NULL, NULL,
                                     NULL};

int find_device(char *ifname, bpf_u_int32 *net, bpf_u_int32 *mask) {
  pcap_if_t *temp = NULL, *ifs = NULL;
  char err[PCAP_ERRBUF_SIZE];

  if (ifname == NULL) {
    log_error("ifname is NULL");
    return -1;
  }

  if (pcap_findalldevs(&ifs, err) == -1) {
    log_error("pcap_findalldevs fail with error %s", err);
    return -1;
  }

  for (temp = ifs; temp; temp = temp->next) {
    log_trace("Checking interface %s (%s)", temp->name, temp->description);
    if (strcmp(temp->name, ifname) == 0) {
      if (pcap_lookupnet(ifname, net, mask, err) == -1) {
        log_error("Can't get netmask for device %s\n", ifname);
        return -1;
      }

      pcap_freealldevs(ifs);
      return 1;
    }
  }

  pcap_freealldevs(ifs);
  return 0;
}

void receive_pcap_packet(u_char *args, const struct pcap_pkthdr *header,
                         const u_char *packet) {

  struct pcap_context *ctx = (struct pcap_context *)args;
  char *ltype = (char *)pcap_datalink_val_to_name(pcap_datalink(ctx->pd));

  if (ctx->pcap_fn != NULL) {
    ctx->pcap_fn(ctx->fn_ctx, (void *)ctx, ltype, (struct pcap_pkthdr *)header,
                 (uint8_t *)packet);
  }
}

int capture_pcap_packet(struct pcap_context *ctx) {
  return pcap_dispatch(ctx->pd, -1, receive_pcap_packet, (u_char *)ctx);
}

void close_pcap(struct pcap_context *ctx) {
  if (ctx != NULL) {
    if (ctx->pd != NULL) {
      pcap_close(ctx->pd);
    }
    os_free(ctx);
  }
}

int capture_pcap_start(struct pcap_context *ctx) {
  if (ctx != NULL) {
    return pcap_loop(ctx->pd, -1, receive_pcap_packet, (u_char *)ctx);
  } else {
    log_error("ctx is NULL");
    return -1;
  }
}

void capture_pcap_stop(struct pcap_context *ctx) {
  if (ctx != NULL) {
    pcap_breakloop(ctx->pd);
  }
}

int get_pcap_datalink(struct pcap_context *ctx) {
  if (ctx != NULL) {
    return pcap_datalink(ctx->pd);
  } else {
    log_error("ctx is NULL");
    return -1;
  }
}

int run_pcap(char *interface, bool immediate, bool promiscuous, int timeout,
             char *filter, bool nonblock, capture_callback_fn pcap_fn,
             void *fn_ctx, struct pcap_context **pctx) {
  int ret;
  char err[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask, net;
  char ip_str[OS_INET_ADDRSTRLEN], mask_str[OS_INET_ADDRSTRLEN];
  struct bpf_program fp;
  struct pcap_context *ctx = NULL;

  if (find_device(interface, &net, &mask) > 0) {
    if(bit32_2_ip((uint32_t)net, ip_str) == NULL) {
      log_errno("Converting %d to IP failed", net);
      return -1;
    }
    if(bit32_2_ip((uint32_t)mask, mask_str) == NULL) {
      log_errno("Converting %d to IP mask failed", mask);
      return -1;
    }
    log_debug("Found device=%s IP=" IPSTR " netmask=" IPSTR, interface,
              IP2STR(ip_str), IP2STR(mask_str));
  }

  ctx = os_zalloc(sizeof(struct pcap_context));
  *pctx = ctx;

  os_strlcpy(ctx->ifname, interface, IFNAMSIZ);
  ctx->pcap_fn = pcap_fn;
  ctx->fn_ctx = fn_ctx;
  if ((ctx->pd = pcap_create(interface, err)) == NULL) {
    log_error("Couldn't open device %s: %s", interface, err);
    os_free(ctx);
    *pctx = NULL;
    return -1;
  }

  if ((ret = pcap_set_snaplen(ctx->pd, PCAP_SNAPSHOT_LENGTH)) < 0) {
    log_error("pcap_set_snaplen fail %d", ret);
    goto fail;
  }

  if ((ret = pcap_set_immediate_mode(ctx->pd, immediate)) < 0) {
    log_error("pcap_set_immediate_mode fail %d", ret);
    goto fail;
  }

  if ((ret = pcap_set_promisc(ctx->pd, promiscuous)) < 0) {
    log_error("pcap_set_promisc fail: %d", ret);
    goto fail;
  }

  if ((ret = pcap_set_timeout(ctx->pd, timeout)) < 0) {
    log_error("pcap_set_timeout fail: %d", ret);
    goto fail;
  }

  if ((ret = pcap_set_buffer_size(ctx->pd, PCAP_BUFFER_SIZE)) < 0) {
    log_error("pcap_set_buffer_size fail: %d", ret);
    goto fail;
  }

  if ((ret = pcap_activate(ctx->pd)) < 0) {
    log_error("pcap_activate fail: %d", ret);
    goto fail;
  }

  /* Compile and apply the filter */
  if (filter != NULL) {
    if (strlen(filter)) {
      if (pcap_compile(ctx->pd, &fp, filter, 0, mask) == -1) {
        log_error("Couldn't parse filter %s: %s\n", filter,
                  pcap_geterr(ctx->pd));
        goto fail;
      }

      log_trace("Setting filter to=%s", filter);
      if (pcap_setfilter(ctx->pd, &fp) == -1) {
        log_error("Couldn't set filter %s: %s\n", filter, pcap_geterr(ctx->pd));
        pcap_freecode(&fp);
        goto fail;
      }

      pcap_freecode(&fp);
    }
  }

  if ((ctx->pcap_fd = pcap_get_selectable_fd(ctx->pd)) == -1) {
    log_error("pcap device doesn't support file descriptors");
    goto fail;
  }

  log_debug("Capture started on %s with link_type=%s", interface,
            pcap_datalink_val_to_name(pcap_datalink(ctx->pd)));

  if (nonblock) {
    log_trace("Setting nonblock mode");
    if (pcap_setnonblock(ctx->pd, 1, err) < 0) {
      log_error("pcap_setnonblock fail: %s", err);
      goto fail;
    }
  }

  log_trace("Non-blocking state %d", pcap_getnonblock(ctx->pd, err));

  return 0;

fail:
  close_pcap(ctx);
  *pctx = NULL;
  return -1;
}

int dump_file_pcap(struct pcap_context *ctx, char *file_path,
                   struct pcap_pkthdr *header, uint8_t *packet) {
  pcap_dumper_t *dumper;
  if ((dumper = pcap_dump_open(ctx->pd, file_path)) == NULL) {
    log_error("pcap_dump_open fail");
    return -1;
  }
  pcap_dump((u_char *)dumper, header, packet);
  pcap_dump_close(dumper);
  return 0;
}

int inject_pcap(struct pcap_context *ctx, uint8_t *packet, size_t size) {
  int sent = pcap_inject(ctx->pd, packet, size);

  if (sent < 0) {
    log_error("pcap_inject fail: %s", pcap_geterr(ctx->pd));
    return -1;
  }

  return sent;
}

void free_pcap_list(UT_array *ctx_list) {
  struct pcap_context **p = NULL;

  if (ctx_list == NULL) {
    return;
  }

  while ((p = (struct pcap_context **)utarray_next(ctx_list, p)) != NULL) {
    close_pcap(*p);
  }

  utarray_free(ctx_list);
}

UT_array *create_pcap_list(void) {
  UT_array *ctx_list = NULL;
  utarray_new(ctx_list, &pcap_list_icd);

  return ctx_list;
}
