/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @brief File containing the implementation of the subscriber events structure.
 */

#include <sys/un.h>
#include <inttypes.h>
#include <stdbool.h>

#include "supervisor_config.h"
#include "subscriber_events.h"

#include "../utils/sockctl.h"
#include "../utils/utarray.h"
#include "../utils/log.h"

#define MAX_SEND_EVENTS_BUF_SIZE 4096

int compare_client_addresses(const struct client_address *a,
                             const struct client_address *b) {
  if (a->type != b->type) {
    return -1;
  } else {
    if (a->type == SOCKET_TYPE_DOMAIN) {
      return os_memcmp(a->caddr.addr_un.sun_path, b->caddr.addr_un.sun_path,
                       a->len);
    } else if (a->type == SOCKET_TYPE_UDP) {
      if (a->caddr.addr_in.sin_port != b->caddr.addr_in.sin_port) {
        return (a->caddr.addr_in.sin_port < b->caddr.addr_in.sin_port) ? -1 : 1;
      } else {
        return os_memcmp(&a->caddr.addr_in.sin_addr, &b->caddr.addr_in.sin_addr,
                         sizeof(struct in_addr));
      }
    } else
      return -1;
  }
}

int sort_subscribers_array(const void *a, const void *b) {
  struct client_address *a_el = (struct client_address *)a;
  struct client_address *b_el = (struct client_address *)b;

  if (a_el->len != b_el->len)
    return (a_el->len < b_el->len) ? -1 : (a_el->len > b_el->len);
  else
    return compare_client_addresses(a, b);
}

int add_events_subscriber(struct supervisor_context *context,
                          struct client_address *addr) {
  struct client_address *p = NULL;

  p = utarray_find(context->subscribers_array, addr, sort_subscribers_array);
  if (p != NULL) {
    log_trace("Client already subscribed with size=%d", p->len);
    return 0;
  }

  utarray_push_back(context->subscribers_array, addr);
  utarray_sort(context->subscribers_array, sort_subscribers_array);
  return 0;
}

int send_events(struct supervisor_context *context, char *name,
                const char *format, va_list args) {
  struct client_address *p = NULL;
  char *send_buf = NULL;
  char args_buf[MAX_SEND_EVENTS_BUF_SIZE];

  if (context->subscribers_array == NULL) {
    return 0;
  }

  vsnprintf(args_buf, MAX_SEND_EVENTS_BUF_SIZE, format, args);

  if ((send_buf = os_zalloc(strlen(name) + strlen(args_buf) + 2)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  sprintf(send_buf, "%s %s\n", name, args_buf);

  while ((p = (struct client_address *)utarray_next(context->subscribers_array,
                                                    p)) != NULL) {
    int sock = (p->type == SOCKET_TYPE_DOMAIN) ? context->domain_sock
                                               : context->udp_sock;
    if (write_socket_data(sock, send_buf, strlen(send_buf), p) <= 0) {
      log_trace("Error sending event with size=%d and type=%d", p->len,
                p->type);
    }
  }

  os_free(send_buf);
  return 0;
}

int send_events_subscriber(struct supervisor_context *context,
                           enum SUBSCRIBER_EVENT type, const char *format,
                           ...) {
  va_list args;
  va_start(args, format);
  switch (type) {
    case SUBSCRIBER_EVENT_IP:
      log_trace("Sending event IP...");
      return send_events(context, EVENT_IP_TEXT, format, args);
      break;
    case SUBSCRIBER_EVENT_AP:
      log_trace("Sending event AP...");
      return send_events(context, EVENT_AP_TEXT, format, args);
      break;
    default:
      log_trace("No event specified");
      return -1;
  }

  va_end(args);
  return 0;
}
