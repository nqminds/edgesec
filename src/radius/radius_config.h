/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file radius_config.h
 * @author Alexandru Mereacre
 * @brief File containing the definition of the radius config.
 */

#ifndef RADIUS_CONFIG_H
#define RADIUS_CONFIG_H

#include "../utils/os.h"

#define RADIUS_SECRET_LEN 255

/**
 * @brief Radius configuration structure
 *
 */
struct radius_conf {
  int radius_port;                       /**< Radius port */
  char radius_client_ip[IP_LEN];         /**< Radius client IP string */
  int radius_client_mask;                /**< Radius client IP mask string */
  char radius_server_ip[IP_LEN];         /**< Radius server IP string */
  int radius_server_mask;                /**< Radius server IP mask string */
  char radius_secret[RADIUS_SECRET_LEN]; /**< Radius secret string */
};

#endif
