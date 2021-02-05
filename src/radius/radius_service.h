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
 * @file radius_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the radius service.
 */

#ifndef RADIUS_SERVICE_H
#define RADIUS_SERVICE_H

/**
 * @brief Runs the radius service
 * 
 * @param hconf The hostapd configuration structure
 * @param rconf The radius configuration structure
 * @param ctrl_if_path The path of the hostapd control interface
 * @return int 0 on success, -1 on error
 */
int run_radius(struct hostapd_conf *hconf, struct radius_conf *rconf, char *ctrl_if_path);

/**
 * @brief Closes the radius service
 * 
 * @param sock Not used
 * @return true success, false otherwise
 */
bool close_radius(int sock);

#endif