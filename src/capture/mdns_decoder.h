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
 * @file mdns_decoder.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the mdns packet decoder utilities.
 */

#ifndef MDNS_DECODER_H
#define MDNS_DECODER_H

#include "capture_config.h"
#include "packet_decoder.h"

/**
 * @brief Decode mdns packet
 * 
 * @param cpac The capture packet structure
 * @return true Success, false otherwise
 */
bool decode_mdns_packet(struct capture_packet *cpac);
#endif
