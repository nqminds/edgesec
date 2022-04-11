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
 * @file subscriber_events.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the subscriber events structure.
 */

#include <sys/un.h>
#include <inttypes.h>
#include <stdbool.h>

#include "supervisor_config.h"
#include "subscriber_events.h"

#include "../utils/domain.h"
#include "../utils/utarray.h"
#include "../utils/log.h"

#define MAX_SEND_EVENTS_BUF_SIZE    4096

int sort_subscribers_arrray(const void *a, const void *b) {
  struct client_address *a_el = (struct client_address *)a;
  struct client_address *b_el = (struct client_address *)b;

  if (a_el->len != b_el->len)
    return (a_el->len < b_el->len) ? -1 : (a_el->len > b_el->len);
  else return os_memcmp(&a_el->addr, &b_el->addr, a_el->len);
}

int add_events_subscriber(struct supervisor_context *context, struct client_address *addr)
{
  struct client_address *p = NULL;

  p = utarray_find(context->subscribers_array, addr, sort_subscribers_arrray);
  if (p != NULL) {
    log_trace("Client already subscribed with size=%d", p->len);
    return 0;
  }

  utarray_push_back(context->subscribers_array, addr);
  utarray_sort(context->subscribers_array, sort_subscribers_arrray);
  return 0;
}

int send_events(struct supervisor_context *context,
                           char *name, const char *format, va_list args)
{
  struct client_address *p = NULL;
  char *send_buf = NULL;
  char args_buf[MAX_SEND_EVENTS_BUF_SIZE];
  vsnprintf(args_buf, MAX_SEND_EVENTS_BUF_SIZE, format, args);

  if ((send_buf = os_zalloc(strlen(name) + strlen(args_buf) + 2)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  sprintf(send_buf, "%s %s", name, args_buf);

  while((p = (struct client_address *) utarray_next(context->subscribers_array, p)) != NULL) {
    if (write_domain_data(context->domain_sock, send_buf, strlen(send_buf), p) <= 0) {
      log_trace("Error sending event to client with size=%d", p->len);
    }
  }

  os_free(send_buf);
  return 0;
}

int send_events_subscriber(struct supervisor_context *context,
                           enum SUBSCRIBER_EVENT type, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  switch(type) {
    case SUBSCRIBER_EVENT_ALERT:
      return send_events(context, EVENT_ALERT_TEXT, format, args);
      break;
    case SUBSCRIBER_EVENT_IP:
      return send_events(context, EVENT_IP_TEXT, format, args);
      break;
    case SUBSCRIBER_EVENT_AP:
      return send_events(context, EVENT_AP_TEXT, format, args);
      break;
    default:
      log_trace("No event specified");
      return -1;
  }

  va_end(args);
  return 0;
}