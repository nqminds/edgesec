/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the tap middleware utilities.
 */

#ifndef TAP_MIDDLEWARE_H
#define TAP_MIDDLEWARE_H

#include "../../middleware.h"

/**
 * @brief TAP Capture Middleware.
 * The TAP capture middleware stores mirrors the trafic from the
 * capture interface to an output interface.
 * @authors Alexandru Mereacre
 */
extern struct capture_middleware tap_middleware;
#endif
