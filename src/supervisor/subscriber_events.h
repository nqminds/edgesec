/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the subscriber events structure.
 */

#ifndef SUBSCRIBER_EVENTS_H
#define SUBSCRIBER_EVENTS_H

#include <sys/un.h>
#include <inttypes.h>
#include <stdbool.h>

#include "supervisor_config.h"

#include "../utils/sockctl.h"
#include "../utils/utarray.h"

enum SUBSCRIBER_EVENT {
  SUBSCRIBER_EVENT_NONE = 0,
  SUBSCRIBER_EVENT_IP,
  SUBSCRIBER_EVENT_AP,
};

#define EVENT_IP_TEXT "IP"
#define EVENT_AP_TEXT "AP"

/**
 * @brief Add a subscriber to the subscriber events array
 *
 * @param context The supervisor context
 * @param addr The subscriber address
 * @return 0 on success, -1 on failure
 */
int add_events_subscriber(struct supervisor_context *context,
                          struct client_address *addr);

/**
 * @brief Send an event to the subscribers array
 *
 * @param context The supervisor context
 * @param type The event type
 * @param format The event text
 * @return 0 on success, -1 on failure
 */
int send_events_subscriber(struct supervisor_context *context,
                           enum SUBSCRIBER_EVENT type, const char *format, ...);
#endif
