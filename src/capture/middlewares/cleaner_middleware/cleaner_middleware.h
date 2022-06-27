/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the middleware cleaner utilities.
 */

#ifndef CLEANER_MIDDLEWARE_H
#define CLEANER_MIDDLEWARE_H

#include "../../middleware.h"

/**
 * @brief Cleaner Middleware.
 * The cleaner middleware is designed to periodically remove the oldest
 * PCAP files when the use more than `CLEANER_STORE_SIZE` KiB.
 * @author Alexandru Mereacre, Alois Klink
 */
extern struct capture_middleware cleaner_middleware;
#endif
