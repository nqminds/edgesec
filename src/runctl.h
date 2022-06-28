/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the service runners.
 */
#ifndef ENGINE_H
#define ENGINE_H

// #include <net/if.h>
#include <inttypes.h>
#include <stdbool.h>

#include "config.h"
#include "supervisor/supervisor_config.h"

/**
 * @brief Initialises the app context structure
 *
 * @param app_config The app config structure
 * @param ctx The app context structure
 * @return 0 on success, -1 otherwise
 */
int init_context(struct app_config *app_config, struct supervisor_context *ctx);

/**
 * @brief Executes the edgesec WiFi networking engine. Creates subnets and
 * starts the supervisor, radius servers and hostapd service.
 *
 * @param app_config The app configuration structures, setting WiFi network
 * config params.
 * @return @c 0 if succes, @c -1 if a service fails to start.
 */
int run_ctl(struct app_config *app_config);

#endif
