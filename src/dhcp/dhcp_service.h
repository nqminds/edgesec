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
 * @file dhcp_service.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of dhcp service configuration utilities.
 */
#ifndef DHCP_SERVICE_H
#define DHCP_SERVICE_H

#include "../utils/os.h"
#include "../utils/utarray.h"


/**
 * @brief The dhcp configuration structures.
 * 
 */
struct dhcp_conf {
  char dhcp_conf_path[MAX_OS_PATH_LEN];                 /**< The dhcp config path string */
  char dhcp_script_path[MAX_OS_PATH_LEN];               /**< The dhcp executable script path string */
};

#endif