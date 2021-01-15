/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file iptables.h
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the IP tables utilities.
 */

#ifndef IPTABLES_H_
#define IPTABLES_H_

#include <inttypes.h>
#include <stdbool.h>
/**
 * @brief Initialises the iptables rules list
 * 
 * @param path The iptables binary path
 * @param ifinfo_array Array of interface configuration info structure
 * @return true on success, false on error
 */
bool init_iptables(char *path, UT_array *ifinfo_array);

/**
 * @brief Free the iptables rules list
 * 
 */
void free_iptables(void);

/**
 * @brief Add a bridge rule to the list of rules
 * 
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param dip Destination IP string
 * @param dif Destination interface name string
 * @return true on sucess, false on error
 */
bool add_bridge_rules(char *sip, char *sif, char *dip, char *dif);

/**
 * @brief Delete a bridge rule
 * 
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param dip Destination IP string
 * @param dif Destination interface name string
 * @return true on sucess, false on error
 */
bool delete_bridge_rules(char *sip, char *sif, char *dip, char *dif);

/**
 * @brief Add a NAT rule
 * 
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param nif NAT interface name string
 * @return true on sucess, false on error
 */
bool add_nat_rules(char *sip, char *sif, char *nif);

/**
 * @brief Delete a NAT rule
 * 
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param nif NAT interface name string
 * @return true on sucess, false on error
 */
bool delete_nat_rules(char *sip, char *sif, char *nif);

#endif