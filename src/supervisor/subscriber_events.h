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
