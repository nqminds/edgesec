/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the pcap middleware utilities.
 */

#ifndef PCAP_MIDDLEWARE_H
#define PCAP_MIDDLEWARE_H

#include "../../middleware.h"

/**
 * @brief PCAP Capture Middleware.
 * The PCAP capture middleware stores the full PCAP data from captured
 * middlewares. Because this is a lot of data, we recommended using the
 * ::cleaner_middleware too, to automatically cleanup/delete old PCAP files.
 * @authors Alexandru Mereacre, Alois Klink
 */
extern struct capture_middleware pcap_middleware;
#endif
