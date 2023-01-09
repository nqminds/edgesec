/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the radius config.
 */

#ifndef RADIUS_CONFIG_H
#define RADIUS_CONFIG_H

#include "../utils/net.h"
// #include "../utils/os.h"

#define RADIUS_SECRET_LEN 255

/**
 * @brief Radius configuration structure
 *
 */
struct radius_conf {
  char client_conf_path[MAX_OS_PATH_LEN];  /**< The client config path string */
  int radius_port;                           /**< Radius port */
  char radius_client_ip[OS_INET_ADDRSTRLEN]; /**< Radius client IP string */
  int radius_client_mask; /**< Radius client IP mask string */
  char radius_server_ip[OS_INET_ADDRSTRLEN]; /**< Radius server IP string */
  int radius_server_mask;                /**< Radius server IP mask string */
  char radius_secret[RADIUS_SECRET_LEN]; /**< Radius secret string */
};

typedef struct mac_conn_info (*mac_conn_fn)(uint8_t mac_addr[],
                                            void *mac_conn_arg);

struct radius_context {
  struct radius_server_conf conf;
  struct radius_server_data *srv;
};
#endif
